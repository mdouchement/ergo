package tcp

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// Relay copies between local and remote bidirectionally. Returns number of
// bytes copied from remote to local, from local to remote, and any error occurred.
// Borrowed from: https://github.com/shadowsocks/go-shadowsocks2
func Relay(local, remote net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	delay := time.Second

	wg.Add(1)
	go func() {
		defer wg.Done()

		_, err1 = io.Copy(remote, local)
		remote.SetDeadline(time.Now().Add(delay)) // wake up the other goroutine blocking on remote
	}()

	_, err = io.Copy(local, remote)
	local.SetDeadline(time.Now().Add(delay)) // wake up the other goroutine blocking on local

	wg.Wait()

	if err1 != nil {
		return err1
	}
	return err
}

// IsIgnorableError returns true if the net error is ignorable.
func IsIgnorableError(err error) bool {
	err = errors.Cause(err)

	ok := strings.HasSuffix(err.Error(), "no such host") ||
		strings.HasSuffix(err.Error(), "connection reset by peer") ||
		strings.HasSuffix(err.Error(), "connection refused")
	if ok {
		return ok
	}

	if err, ok := err.(*net.OpError); ok {
		return err.Timeout()
	}

	if err, ok := err.(net.Error); ok {
		return err.Timeout()
	}
	return false
}
