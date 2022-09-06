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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/msaf1980/sshdog/dbg"
	"golang.org/x/crypto/ssh"
)

// Manage the SSH Server
type Server struct {
	ServerConfig   ssh.ServerConfig
	Socket         net.Listener
	AuthorizedKeys map[string]bool
	keyDir         string // used only for per-user auth keys only
	PasswordMap    map[string]string
	stop           chan bool
	done           chan bool
	mu             sync.RWMutex
	shutdown       bool
	conns          map[*ServerConn]struct{}
	connWg         sync.WaitGroup
}

var (
	KeyNames = []string{
		"ssh_host_dsa_key",
		"ssh_host_ecdsa_key",
		"ssh_host_rsa_key",
	}
	ErrWrongPassword       = errors.New("Wrong password")
	ErrDisablePasswordAuth = errors.New("Password auth are diabled")
	ErrUnknownPubKey       = errors.New("No valid key found.")
)

// NewServer create new server instance with global authorized keys (load before start with AddAuthorizedKeys)
func NewServer() *Server {
	s := &Server{
		stop:           make(chan bool),
		done:           make(chan bool, 1),
		conns:          make(map[*ServerConn]struct{}),
		AuthorizedKeys: make(map[string]bool),
		PasswordMap:    make(map[string]string),
	}

	s.ServerConfig.PublicKeyCallback = s.VerifyPublicKey
	s.ServerConfig.PasswordCallback = s.VerifyPassword

	return s
}

// NewServer create new server instance with per-user authorized keys (stored in keyDir)
func NewServerPerUser(keyDir string) (*Server, error) {
	if keyDir == "" {
		return nil, errors.New("key dir empty")
	}
	s := &Server{
		keyDir:         keyDir,
		stop:           make(chan bool),
		done:           make(chan bool, 1),
		conns:          make(map[*ServerConn]struct{}),
		AuthorizedKeys: make(map[string]bool),
		PasswordMap:    make(map[string]string),
	}

	s.ServerConfig.PublicKeyCallback = s.VerifyUserPublicKey
	s.ServerConfig.PasswordCallback = s.VerifyPassword

	return s, nil
}

func (s *Server) listen(addr string) error {
	if sock, err := net.Listen("tcp", addr); err != nil {
		dbg.Debug("Unable to listen: %v", err)
		return err
	} else {
		dbg.Debug("Listening on %s", addr)
		s.Socket = sock
	}
	return nil
}

func (s *Server) acceptChannel() <-chan net.Conn {
	c := make(chan net.Conn)
	go func() {
		defer close(c)
		for {
			conn, err := s.Socket.Accept()
			if err != nil {
				dbg.Debug("Unable to accept: %v", err)
				return
			}
			dbg.Debug("Accepted connection from: %s", conn.RemoteAddr())
			c <- conn
		}
	}()
	return c
}

func (s *Server) handleConn(conn net.Conn) {
	sConn, err := NewServerConn(conn, s)
	if err != nil {
		if err == io.EOF {
			dbg.Debug("Connection closed by remote host.")
			return
		}
		dbg.Debug("Unable to negotiate SSH: %v", err)
		return
	}
	dbg.Debug("Authenticated client from: %s", sConn.RemoteAddr())

	go sConn.HandleConn()
}

func (s *Server) serveLoop() error {
	acceptChan := s.acceptChannel()
	defer func() {
		dbg.Debug("done serveLoop")
		s.Socket.Close()
		s.done <- true
	}()
	for {
		dbg.Debug("select...")
		select {
		case conn, ok := <-acceptChan:
			if ok {
				s.handleConn(conn)
			} else {
				dbg.Debug("failed to accept")
				acceptChan = nil
				return nil
			}
		case <-s.stop:
			dbg.Debug("Stop signal received, stopping.")
			return nil
		}
	}
}

func (s *Server) ListenAndServe(port int16) (error, func()) {
	addr := ":" + strconv.Itoa(int(port))
	if err := s.listen(addr); err != nil {
		return err, nil
	}
	go s.serveLoop()
	return nil, s.Stop
}

func (s *Server) ListenAndServe2(addr string) (error, func()) {
	if err := s.listen(addr); err != nil {
		return err, nil
	}
	go s.serveLoop()
	return nil, s.Stop
}

func (s *Server) ListenAndServeForever(port int16) error {
	if err, _ := s.ListenAndServe(port); err != nil {
		return err
	}
	s.Wait()
	return nil
}

func (s *Server) ListenAndServeForever2(addr string) error {
	if err, _ := s.ListenAndServe2(addr); err != nil {
		return err
	}
	s.Wait()
	return nil
}

func (s *Server) Address() string {
	if s.Socket == nil {
		return ""
	}
	return s.Socket.Addr().String()
}

func (s *Server) HostAndPort() (string, string) {
	addr := s.Address()
	p := strings.LastIndexByte(addr, ':')
	if p < 0 {
		return "", ""
	}
	return addr[:p], addr[p+1:]
}

// Wait for server shutdown
func (s *Server) Wait() {
	dbg.Debug("Waiting for shutdown.")
	<-s.done
}

func (s *Server) GetDoneChan() chan bool {
	return s.done
}

// Ask for shutdown
func (s *Server) Stop() {
	dbg.Debug("requesting shutdown.")
	s.stop <- true
	s.mu.Lock()
	dbg.Debug("Cancel %d sessions.", len(s.conns))
	s.shutdown = true
	for conn := range s.conns {
		if conn.cancel != nil {
			conn.cancel()
		}
	}
	s.mu.Unlock()
	s.connWg.Wait()
	close(s.stop)
	dbg.Debug("shutdown.")
}

func (s *Server) AddAuthorizedKeys(keyData []byte) *Server {
	if s.keyDir == "" {
		dbg.Debug("skip, per-user authorized keys enabled")
		return s
	}
	for len(keyData) > 0 {
		newKey, _, _, left, err := ssh.ParseAuthorizedKey(keyData)
		keyData = left
		if err != nil {
			dbg.Debug("Error parsing key: %v", err)
			break
		}
		s.AuthorizedKeys[string(newKey.Marshal())] = true
	}
	return s
}

func (s *Server) AddUser(user, password string) *Server {
	if user == "" || password == "" {
		dbg.Debug("Empty username or password")
	} else {
		s.PasswordMap[user] = password
	}
	return s
}

func (s *Server) VerifyPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if _, ok := s.AuthorizedKeys[string(key.Marshal())]; !ok {
		dbg.Debug("Key not found!")
		return nil, ErrUnknownPubKey
	}
	return &ssh.Permissions{
		// Record the public key used for authentication.
		Extensions: map[string]string{
			"pubkey-fp": ssh.FingerprintSHA256(key),
		},
	}, nil
}

func (s *Server) readUserAuthKeys(u string) (map[string]bool, error) {
	keysPath := path.Join(s.keyDir, u)
	keyData, err := os.ReadFile(keysPath)
	if err != nil {
		dbg.Debug("Failed to load authorized_keys %s, err: %v", keysPath, err)
		return nil, ErrUnknownPubKey
	}

	authorizedKeys := make(map[string]bool)
	for len(keyData) > 0 {
		newKey, _, _, left, err := ssh.ParseAuthorizedKey(keyData)
		keyData = left
		if err != nil {
			dbg.Debug("Error parsing key: %v", err)
			break
		}
		authorizedKeys[string(newKey.Marshal())] = true
	}
	return authorizedKeys, nil
}

func (s *Server) VerifyUserPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	authorizedKeys, err := s.readUserAuthKeys(conn.User())
	if err != nil {
		return nil, err
	}
	if _, exist := authorizedKeys[string(key.Marshal())]; exist {
		return &ssh.Permissions{
			// Record the public key used for authentication.
			Extensions: map[string]string{
				"pubkey-fp": ssh.FingerprintSHA256(key),
			},
		}, nil
	}
	return nil, ErrUnknownPubKey
}

func (s *Server) VerifyPassword(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	if len(s.PasswordMap) == 0 {
		return nil, ErrDisablePasswordAuth
	}
	user := conn.User()
	if password, exist := s.PasswordMap[user]; exist {
		if string(pass) == password {
			return nil, nil
		} else {
			return nil, ErrWrongPassword
		}
	} else {
		return nil, errors.New(user + " not exist")
	}
}

func (s *Server) AddHostkey(keyData []byte) error {
	key, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		s.ServerConfig.AddHostKey(key)
		return nil
	}
	return err
}

func (s *Server) AddHostkeyFrom(keypath string) error {
	buf, err := ioutil.ReadFile(keypath)
	if err != nil {
		return err
	}
	return s.AddHostkey(buf)
}

func (s *Server) RandomHostkey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return err
	}
	s.ServerConfig.AddHostKey(signer)
	return nil
}
