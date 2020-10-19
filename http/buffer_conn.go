package http

import "net"

type BufferConn struct {
	net.Conn
	Reader
}

func NewBufferConn(c net.Conn) *BufferConn {
	return &BufferConn{
		Conn:   c,
		Reader: NewReader(c),
	}
}

func (b *BufferConn) Drop() error {
	const size = 512
	b.Reader.Reset()

	if b.IsAllRead() {
		return nil
	}

	p := make([]byte, size)
	for {
		n, err := b.Read(p)
		if err != nil {
			return err
		}

		if n < size {
			return nil
		}
	}
}

func (b *BufferConn) Read(p []byte) (n int, err error) {
	return b.Reader.Read(p)
}

func (b *BufferConn) Write(p []byte) (n int, err error) {
	return b.Conn.Write(p)
}
