package sshtest

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func newClientSession(t *testing.T, addr string, config *ssh.ClientConfig) (*ssh.Session, *ssh.Client, func()) {
	if config == nil {
		config = &ssh.ClientConfig{
			User: "testuser",
			Auth: []ssh.AuthMethod{
				ssh.Password("testpass"),
			},
		}
	}
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return session, client, func() {
		session.Close()
		client.Close()
	}
}
