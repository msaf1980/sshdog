package sshtest

import (
	"github.com/msaf1980/sshdog"
)

// Manage the SSH Server
type Server struct {
	*sshdog.Server
}

// NewServer create new server instance with global authorized keys (load before start with AddAuthorizedKeys)
func NewServer() *Server {
	s := &Server{
		sshdog.NewServer(),
	}

	return s
}

// NewServer create new server instance with per-user authorized keys (stored in keyDir)
func NewServerPerUser(keyDir string) (*Server, error) {
	b, err := sshdog.NewServerPerUser(keyDir)
	if err != nil {
		return nil, err
	}

	s := &Server{b}

	return s, nil
}

func (s *Server) ListenAndServe() (error, func()) {
	addr := "127.0.0.1:0"
	err, stop := s.ListenAndServe2(addr)
	if err != nil {
		addr = "[::1]:0"
		err, stop = s.ListenAndServe2(addr)
	}

	return err, stop
}

func (s *Server) ListenAndServeForever() error {
	if err, _ := s.ListenAndServe(); err != nil {
		return err
	}
	s.Wait()
	return nil
}
