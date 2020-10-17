package http

import (
	"net"

	"github.com/pkg/errors"
)

func Proxy(c net.Conn) (net.Conn, Header, error) {
	buf := NewBufferConn(c)
	header, err := Parse(buf)
	if err != nil {
		return c, header, errors.Wrap(err, "http proxy")
	}

	if header.Method == "CONNECT" {
		// The CONNECT request is made for the proxy to enable HTTPS with the remote.
		// We drop all the data the remaining data to let the client perform the TLS handshake.
		err = buf.Drop()
		if err != nil {
			return c, header, errors.Wrap(err, "http proxy")
		}
	} else {
		// We write the header without proxy details.
		buf.Prepend(header.format(hopHeaders).Bytes())
	}

	return buf, header, nil
}
