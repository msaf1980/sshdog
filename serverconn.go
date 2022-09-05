// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: High-level file comment.
package sshdog

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/google/shlex"
	"github.com/msaf1980/sshdog/dbg"
	"github.com/msaf1980/sshdog/pty"
	"golang.org/x/crypto/ssh"
)

// Handling for a single incoming connection
type ServerConn struct {
	*Server
	*ssh.ServerConn
	pty        *pty.Pty
	reqs       <-chan *ssh.Request
	chans      <-chan ssh.NewChannel
	environ    []string
	exitStatus uint32
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewServerConn(conn net.Conn, s *Server) (*ServerConn, error) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, &s.ServerConfig)
	if err != nil {
		return nil, err
	}
	return &ServerConn{
		Server:     s,
		ServerConn: sConn,
		reqs:       reqs,
		chans:      chans,
		environ:    os.Environ(),
	}, nil
}

func (conn *ServerConn) ServiceGlobalRequests() {
	for r := range conn.reqs {
		dbg.Debug("Received request %s plus %d bytes.", r.Type, len(r.Payload))
		if r.WantReply {
			r.Reply(true, []byte{})
		}
	}
}

func (conn *ServerConn) trackConn(add bool) bool {
	// mu, conns, connWg are inherited from Server
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if add {
		if conn.shutdown {
			// shutdown initiate
			return true
		}
		conn.conns[conn] = struct{}{}
		conn.connWg.Add(1)
		conn.ctx, conn.cancel = context.WithCancel(context.Background())
	} else {
		delete(conn.conns, conn)
		conn.connWg.Done()
	}
	return false
}

// Handle a single established connection
func (conn *ServerConn) HandleConn() {
	defer func() {
		dbg.Debug("Closing connection to: %s", conn.RemoteAddr())
		conn.Close()
	}()

	go conn.ServiceGlobalRequests()
	wg := &sync.WaitGroup{}

	for newChan := range conn.chans {
		dbg.Debug("Incoming channel request: %s", newChan.ChannelType())
		switch newChan.ChannelType() {
		case "session":
			wg.Add(1)
			go conn.HandleSessionChannel(wg, newChan)
		case "direct-tcpip":
			wg.Add(1)
			go conn.HandleTCPIPChannel(wg, newChan)
		default:
			dbg.Debug("Unable to handle channel request, rejecting.")
			newChan.Reject(ssh.Prohibited, "Prohibited")
		}
	}

	wg.Wait()
}

type PTYRequest struct {
	Term     string
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type EnvRequest struct {
	Name  string
	Value string
}

type ExecRequest struct {
	Cmd string
}

func defaultShell() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"C:\\windows\\system32\\cmd.exe",
			"/Q",
		}
	default:
		return []string{"/bin/sh"}
	}
}

func commandWithShell(command string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"C:\\windows\\system32\\cmd.exe",
			"/C",
			command,
		}
	default:
		return []string{
			"/bin/sh",
			"-c",
			command,
		}
	}
}

func (conn *ServerConn) HandleSessionChannel(wg *sync.WaitGroup, newChan ssh.NewChannel) {
	// TODO: refactor this, too long
	defer wg.Done()
	ch, reqs, err := newChan.Accept()
	if err != nil {
		dbg.Debug("Unable to accept newChan: %v", err)
		return
	}
	defer func() {
		b := ssh.Marshal(struct{ ExitStatus uint32 }{conn.exitStatus})
		ch.SendRequest("exit-status", false, b)
		dbg.Debug("Closing session channel.")
		ch.Close()
	}()

	for req := range reqs {
		var success bool
		switch req.Type {
		case "pty-req":
			ptyreq := &PTYRequest{}
			if err := ssh.Unmarshal(req.Payload, ptyreq); err != nil {
				dbg.Debug("Error unmarshaling pty-req: %v", err)
			}
			conn.pty, err = pty.OpenPty()
			if conn.pty != nil {
				conn.pty.Resize(uint16(ptyreq.Height), uint16(ptyreq.Width), uint16(ptyreq.WidthPx), uint16(ptyreq.HeightPx))
				os.Setenv("TERM", ptyreq.Term)
				// TODO: set pty modes
			}
			if err == nil {
				success = true
			} else {
				dbg.Debug("Failed allocating pty: %v", err)
			}
		case "env":
			envreq := &EnvRequest{}
			if err := ssh.Unmarshal(req.Payload, envreq); err != nil {
				dbg.Debug("Error unmarshaling env: %v", err)
			} else {
				dbg.Debug("env: %s=%s", envreq.Name, envreq.Value)
				conn.environ = append(conn.environ, fmt.Sprintf("%s=%s", envreq.Name, envreq.Value))
				success = true
			}
		case "shell":
			// TODO: get the user's shell
			success = conn.ExecuteForChannel(defaultShell(), ch)
		case "exec":
			execReq := &ExecRequest{}
			if err := ssh.Unmarshal(req.Payload, execReq); err != nil {
				dbg.Debug("Error unmarshaling exec: %v", err)
			} else {
				if cmd, err := shlex.Split(execReq.Cmd); err == nil {
					dbg.Debug("Command: %v", cmd)
					if len(cmd) == 0 {
						// start a shell
						success = conn.ExecuteForChannel(defaultShell(), ch)
					} else if cmd[0] == "scp" {
						if err := conn.SCPHandler(cmd, ch); err != nil {
							dbg.Debug("scp failure: %v", err)
							conn.exitStatus = 1
						}
					} else {
						success = conn.ExecuteForChannel(commandWithShell(execReq.Cmd), ch)
					}
				} else {
					dbg.Debug("Error splitting cmd: %v", err)
				}
			}
			return
		default:
			dbg.Debug("Unknown session request: %s", req.Type)
		}
		if req.WantReply {
			req.Reply(success, []byte{})
		}
	}
}

type exitStatusMsg struct {
	Status uint32
}

// Execute a process for the channel.
func (conn *ServerConn) ExecuteForChannel(shellCmd []string, ch ssh.Channel) bool {
	if conn.trackConn(true) {
		dbg.Debug("Shutdown init, canceled executing %v", shellCmd)
		return false
	}
	dbg.Debug("Executing %v", shellCmd)
	proc := exec.Command(shellCmd[0], shellCmd[1:]...)
	proc.Env = conn.environ
	if userInfo, err := user.Current(); err == nil {
		proc.Dir = userInfo.HomeDir
	}
	if conn.pty == nil {
		stdin, _ := proc.StdinPipe()
		go io.Copy(stdin, ch)
		proc.Stdout = ch
		proc.Stderr = ch
	} else {
		conn.pty.AttachPty(proc)
		conn.pty.AttachIO(ch, ch)
	}

	waitDone := make(chan struct{})
	go func() {
		select {
		case <-conn.ctx.Done():
			dbg.Debug("Killing session.")
			proc.Process.Signal(syscall.SIGTERM)
			select {
			case <-time.After(time.Second):
				proc.Process.Kill()
			case <-waitDone:
			}
		case <-waitDone:
		}
	}()
	err := proc.Run()
	close(waitDone)
	conn.trackConn(false)
	if err == nil {
		dbg.Debug("Finished execution.")
	} else {
		if exitErr, ok := err.(*exec.ExitError); ok {
			conn.exitStatus = uint32(exitErr.ExitCode())
		} else {
			conn.exitStatus = 127
		}
		dbg.Debug("Finished execution with code %d, error: %v", conn.exitStatus, err)
	}
	return true
}

func (conn *ServerConn) Cancel() {
	if conn.cancel != nil {
		conn.cancel()
		conn.cancel = nil
	}
}

// Message for port forwarding
type tcpipMessage struct {
	Host       string
	Port       uint32
	SourceIP   string
	SourcePort uint32
}

func (conn *ServerConn) HandleTCPIPChannel(wg *sync.WaitGroup, newChan ssh.NewChannel) {
	defer wg.Done()
	var msg tcpipMessage
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		dbg.Debug("Unable to setup forwarding: %v", err)
		newChan.Reject(ssh.ResourceShortage, "Error parsing message.")
		return
	}
	dbg.Debug("Forwarding request: %v", msg)

	outbound, err := net.Dial("tcp", fmt.Sprintf("%s:%d", msg.Host, msg.Port))
	if err != nil {
		dbg.Debug("Unable to dial forward: %v", err)
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer outbound.Close()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dbg.Debug("Unable to accept chan: %v", err)
		return
	}
	defer ch.Close()

	go func() {
		for req := range reqs {
			switch req.Type {
			default:
				dbg.Debug("Unknown direct-tcpip request: %s", req.Type)
				if req.WantReply {
					req.Reply(false, []byte{})
				}
			}
		}
	}()
	go io.Copy(ch, outbound)
	io.Copy(outbound, ch)

	dbg.Debug("Closing forwarding request: %v", msg)
}
