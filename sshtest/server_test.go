package sshtest

import (
	"bytes"
	"io"
	"testing"
	"time"
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
		t.Fatalf("session.Run must be ended with error io.EOF, but success with stdout: %s", stdout.String())
	} else if sessErr != io.EOF {
		t.Fatalf("session.Run must be ended with error io.EOF, but return: %v", sessErr)
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

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	var sessErr error
	sess, _, cleanup := newClientSession(t, s.Address(), nil)
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		sessErr = sess.Run("sleep 10")
	}()

	time.Sleep(100 * time.Millisecond)

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
		t.Fatalf("session.Run must be ended with error io.EOF, but success with stdout: %s", stdout.String())
	} else if sessErr != io.EOF {
		t.Fatalf("session.Run must be ended with error io.EOF, but return: %v", sessErr)
	}
}
