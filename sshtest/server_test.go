package sshtest

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServer_SessionClose(t *testing.T) {
	s := NewServer()
	err := s.AddHostkeyFrom("../tests/.ssh/host_rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	s.AddUser("testuser", "testpass")
	err, stop := s.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	var sessErr error
	sess, _, cleanup := newClientSession(t, s.Address(), nil)
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		sessErr = sess.Run("whoami")
	}()

	go func() {
		defer close(closeDoneChan)
		stop()
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
	case <-clientDoneChan:
	}

	if sessErr == nil {
		t.Fatalf("session.Run must be ended with exit code 127, but success with out: %s", stdout.String())
	} else if exitErr, ok := sessErr.(*ssh.ExitError); ok && exitErr.ExitStatus() != 127 || !ok {
		t.Fatalf("session.Run must be ended with exit code 127, but return: %v", sessErr)
	}
}

func TestServer_SessionCancel(t *testing.T) {
	s := NewServer()
	err := s.AddHostkeyFrom("../tests/.ssh/host_rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	s.AddUser("testuser", "testpass")
	err, stop := s.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}

	clientDoneChan := make(chan struct{}, 1)
	closeDoneChan := make(chan struct{}, 1)

	var sessErr error
	sess, _, cleanup := newClientSession(t, s.Address(), nil)
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	go func() {
		defer func() {
			cleanup()
			close(clientDoneChan)
		}()
		sessErr = sess.Run("sleep 10")
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		defer close(closeDoneChan)
		stop()
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Error("timeout session cancel")
		<-clientDoneChan
	case <-clientDoneChan:
	}

	timeout = time.After(10 * time.Second)
	select {
	case <-timeout:
		t.Error("timeout shutdown")
	case <-closeDoneChan:
	}

	if sessErr == nil {
		t.Fatalf("session.Run must be ended with exit code 143 (SIGTERM received), but success with out:\n%s", stdout.String())
	} else if exitErr, ok := sessErr.(*ssh.ExitError); ok && exitErr.ExitStatus() != 143 || !ok {
		t.Fatalf("session.Run must be ended with exit code 143 (SIGTERM received), but return: %v", sessErr)
	}
}

func TestServer_ExitCode(t *testing.T) {
	s := NewServer()
	err := s.AddHostkeyFrom("../tests/.ssh/host_rsa_key")
	if err != nil {
		t.Fatal(err)
	}
	s.AddUser("testuser", "testpass")
	err, stop := s.ListenAndServe()
	if err != nil {
		t.Fatal(err)
	}

	closeDoneChan := make(chan struct{}, 1)

	var sessErr error
	sess, client, cleanup := newClientSession(t, s.Address(), nil)

	var stdout bytes.Buffer

	sess.Stdout = &stdout
	sessErr = sess.Run("exit 1")
	sess.Close()

	if sessErr == nil {
		t.Errorf("session.Run must be ended with exit code 1, but success with out:\n%s", stdout.String())
	} else if exitErr, ok := sessErr.(*ssh.ExitError); ok && exitErr.ExitStatus() != 1 || !ok {
		t.Errorf("session.Run must be ended with exit code 1, but return: %v", sessErr)
	}

	sess, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	sess.Stdout = &stdout
	sessErr = sess.Run("whoami1244_notexitst")

	if sessErr == nil {
		t.Errorf("session.Run must be ended with exit code 127, but success with out:\n%s", stdout.String())
	} else if exitErr, ok := sessErr.(*ssh.ExitError); ok && exitErr.ExitStatus() != 127 || !ok {
		t.Errorf("session.Run must be ended with exit code 127, but return: %v", sessErr)
	} else if !strings.Contains(stdout.String(), "not found") {
		t.Errorf("session.Run must be ended with stderr: 'not found', but success with out:\n%s", stdout.String())
	}

	sess, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	sess.Stdout = &stdout
	sessErr = sess.Run("echo 1")

	if sessErr != nil {
		t.Errorf("session.Run must be ended with exit code 127, but return: %v", sessErr)
	} else if stdout.String() != "1\n" {
		t.Errorf("session.Run must be ended with stdout: '1\\n', but got out:\n%s", stdout.String())
	}

	cleanup()

	go func() {
		defer close(closeDoneChan)
		stop()
	}()

	timeout := time.After(10 * time.Second)
	select {
	case <-timeout:
		t.Error("timeout shutdown")
	case <-closeDoneChan:
	}
}
