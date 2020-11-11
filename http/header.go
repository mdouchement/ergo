package http

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type Header struct {
	// CONNECT raw.githubusercontent.com:443 HTTP/1.1
	Method     string
	RequestURI string
	Proto      string
	// Host: raw.githubusercontent.com:443
	// Proxy-Connection: keep-alive
	// ...
	Header http.Header
}

func Parse(r Reader) (h Header, err error) {
	// Read first line:
	//   CONNECT raw.githubusercontent.com:443 HTTP/1.1
	var s []byte
	if s, err = r.ReadLine(); err != nil {
		return h, err
	}

	var ok bool
	h.Method, h.RequestURI, h.Proto, ok = h.parseRequestLine(s)
	if !ok {
		return h, errors.Errorf("malformed HTTP request %s", s)
	}

	//

	// Subsequent lines:
	//   Host: raw.githubusercontent.com:443
	//   Proxy-Connection: keep-alive
	//   ...
	h.Header = http.Header{}
	for {
		s, err = r.ReadLine()
		if err != nil {
			return h, err
		}
		if len(s) == 0 {
			break
		}

		idx := bytes.Index(s, []byte{':'})
		h.Header.Set(
			string(bytes.TrimSpace(s[:idx])),
			string(bytes.TrimSpace(s[idx+1:])),
		)
	}

	return h, nil
}

func (h *Header) ProxyBasicAuth() (user, password string, ok bool) {
	auth := h.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}

	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func (h *Header) Domain() string {
	host := h.Header.Get("Host")
	idx := strings.Index(host, ":")
	if idx < 1 {
		return host
	}
	return host[:idx]
}

func (h *Header) Host() string {
	host := h.Header.Get("Host")
	if host != "" && !strings.Contains(host, ":") {
		host += ":80"
	}
	return host
}

func (h *Header) Port() string {
	host := h.Header.Get("Host")
	idx := strings.Index(host, ":")
	if idx < 1 {
		return "80"
	}
	return host[idx+1:]
}

func (h *Header) String() string {
	return h.format(nil).String()
}

func (h *Header) format(exclude map[string]bool) *bytes.Buffer {
	b := bytes.NewBuffer(nil)
	b.WriteString(fmt.Sprintf("%s %s %s\r\n", h.Method, h.RequestURI, h.Proto))
	h.Header.WriteSubset(b, exclude)
	b.Write([]byte{'\r', '\n'})

	return b
}

func (h *Header) parseRequestLine(line []byte) (method, requestURI, proto string, ok bool) {
	s1 := bytes.Index(line, []byte{' '})
	s2 := bytes.Index(line[s1+1:], []byte{' '})
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return string(line[:s1]), string(line[s1+1 : s2]), string(line[s2+1:]), true
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = map[string]bool{
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	"Accept-Encoding":     true,
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true, // canonicalized version of "TE"
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Proxy-Connection":    true, // added by CURL  http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/web-proxy-connection-header.html
}
