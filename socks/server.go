package socks5

import (
	"bufio"
	"context"

	//	"fmt"
	"io"
	"log"
	"net"
	//	"os"
	//	"errors"
)

// Config is used to setup and configure a Server
type Config struct {
	//AuthMethods
	//Credentials
	///Resolver NameResolver
	//Rules
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	Addr    string
	Network string
	//config  *Config
	//authMethods auth
}

// ListenAndServe is used to create a listener
func (s *Server) ListenAndServe() error {
	log.Printf("Starting server on %v\n", s.Addr)
	l, err := net.Listen(s.Network, s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		//go
		go s.HandleConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) HandleConn(conn net.Conn) {
	defer conn.Close()
	ctx := context.Background()
	rbuf := bufio.NewReader(conn)
	wbuf := io.Writer(conn)
	if err := Auth(rbuf, wbuf); err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	req, err := NewRequest(rbuf)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return
	}

	// set client fields
	req.ClientAddr = conn.RemoteAddr().(*net.TCPAddr).IP
	req.ClientPort = uint16(conn.RemoteAddr().(*net.TCPAddr).Port)
	req.Conn = conn
	log.Printf("new accepted connection, request Message [%v]", req)
	if err := s.HandleRequest(ctx, req); err != nil {
		log.Printf("Error: %v\n", err)
		return
	}
}
func (s *Server) HandleRequest(ctx context.Context, req *Request) error {
	switch req.Cmd {
	case CommandConnect:
		return s.HandleConnect(ctx, req)
	case CommandAssociate:
		log.Printf("err: Associate cmd not implemented yet")
		return ErrUnsupportedCmd
	case CommandBind:
		log.Printf("err: Bind cmd not implemented yet")
		return ErrUnsupportedCmd
	default:
		log.Printf("err: Can't recognize cmd %v \n", req.Cmd)
		return ErrUnsupportedCmd
	}
}
