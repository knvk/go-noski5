package socks5

import (
	"errors"
	"io"
)

const (
	// Auth methods
	AuthNone          uint8 = 0x00
	AuthPasswd        uint8 = 0x02
	AuthNoAcceptable  uint8 = 0xFF
	AuthSuccess       uint8 = 0x00
	AuthFailure       uint8 = 0x01
	subnegotiationVer uint8 = 0x01
)

var (
	ErrAuthFailure = errors.New("failed auth")
)

type Authenticator interface {
	Authenticate(r io.Reader, w io.Writer) error
}

type NoAuthMethod struct{}

type PassAuthMethod struct {
	Credentials map[string]string
}

func (a NoAuthMethod) Authenticate(r io.Reader, w io.Writer) error {
	_, err := w.Write([]byte{socks5Version, AuthNone})
	if err != nil {
		return err
	}
	return nil
}

func (a PassAuthMethod) Authenticate(r io.Reader, w io.Writer) error {
	w.Write([]byte{socks5Version, AuthPasswd})
	authMsg := &AuthMsg{}
	buf := make([]byte, 2)
	if _, err := r.Read(buf); err != nil {
		return err
	}
	authMsg.Ver = buf[0]
	authMsg.ULen = buf[1]
	if authMsg.Ver != subnegotiationVer {
		return ErrUnsupportedVer
	}
	buf = make([]byte, int(authMsg.ULen)+1)
	if _, err := io.ReadAtLeast(r, buf, int(authMsg.ULen)+1); err != nil {
		return err
	}
	authMsg.User, authMsg.PLen = string(buf[:len(buf)-1]), buf[len(buf)-1]
	buf = make([]byte, authMsg.PLen)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	authMsg.Pass = string(buf)

	pass, ok := a.Credentials[authMsg.User]
	if !ok {
		w.Write([]byte{subnegotiationVer, AuthFailure})
		return ErrAuthFailure
	}
	if authMsg.Pass != pass {
		w.Write([]byte{subnegotiationVer, AuthFailure})
		return ErrAuthFailure
	}
	w.Write([]byte{subnegotiationVer, AuthSuccess})
	return nil
}
