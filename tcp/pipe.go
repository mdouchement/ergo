package tcp

import (
	"net"

	"github.com/pkg/errors"
)

type Pipe struct {
	rc net.Conn
	c  net.Conn
}

func NewPipeTCP(c net.Conn, remote string) (*Pipe, error) {
	rc, err := net.Dial("tcp", remote)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to remote")
	}
	rc.(*net.TCPConn).SetKeepAlive(true)

	return NewPipe(c, rc)
}

func NewPipe(c, rc net.Conn) (*Pipe, error) {
	return &Pipe{
		rc: rc,
		c:  c,
	}, nil
}

func (s *Pipe) Relay() error {
	err := Relay(s.c, s.rc)
	return errors.Wrap(err, "pipe-relay")
}

func (s *Pipe) LocalConn() net.Conn {
	return s.c
}

func (s *Pipe) RemoteConn() net.Conn {
	return s.rc
}

func (s *Pipe) Close() {
	s.c.Close()
	s.rc.Close()
}
