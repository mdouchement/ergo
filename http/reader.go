package http

import (
	"bytes"
	"io"
)

type (
	Reader interface {
		io.Reader
		ReadLine() (line []byte, err error)
		Prepend(p []byte)
		IsAllRead() bool
		Reset()
	}

	reader struct {
		r         io.Reader
		block     int // buffer growing size
		buf       []byte
		size      int
		offset    int
		isAllRead bool
	}
)

func NewReader(r io.Reader) Reader {
	return &reader{
		r:     r,
		block: 512,
	}
}

func (r *reader) ReadLine() (line []byte, err error) {
	var b byte
	buf := bytes.NewBuffer(nil)
	for {
		if r.offset >= r.size {
			err := r.fill()
			if err != nil {
				return nil, err
			}
		}

		b = r.buf[r.offset]
		r.offset++
		if b == '\n' {
			continue
		}
		if b == '\r' {
			return buf.Bytes(), nil
		}

		buf.Write([]byte{b})
	}
}

func (r *reader) fill() error {
	if r.buf == nil {
		r.buf = make([]byte, r.block)
	} else {
		buf := make([]byte, r.size+r.block)
		copy(buf, r.buf)
		r.buf = buf
	}

	n, err := r.r.Read(r.buf[r.size:])
	if err != nil {
		return err
	}
	r.size += n
	r.isAllRead = n < r.block
	r.buf = r.buf[:r.size]
	return err
}

func (r *reader) Prepend(p []byte) {
	l := len(p) - 1
	if l <= r.offset { // Reuse
		r.offset -= l
		copy(r.buf[r.offset:], p)
		return
	}

	buf := make([]byte, len(p)+r.size-r.offset)
	n := copy(buf, p)
	copy(buf[n:], r.buf[r.offset:r.size])

	r.buf = buf
	r.offset = 0
	r.size = len(r.buf)
	return
}

func (r *reader) IsAllRead() bool {
	return r.isAllRead
}

func (r *reader) Reset() {
	r.buf = nil
	r.size = 0
	r.offset = 0
}

func (r *reader) Read(p []byte) (n int, err error) {
	if r.buf == nil {
		return r.r.Read(p)
	}

	n = copy(p, r.buf[r.offset:])
	r.offset += n
	if r.offset >= r.size {
		r.Reset()
	}
	return n, nil
}
