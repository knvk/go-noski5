package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

const (
	// version
	socks5Version uint8 = 0x05
	// cmd
	CommandConnect   uint8 = 0x01
	CommandBind      uint8 = 0x02
	CommandAssociate uint8 = 0x03
	// Atype
	AtypeIP4 uint8 = 0x01
	AtypeDN  uint8 = 0x03
	AtypeIP6 uint8 = 0x04
	// Reply codes
	RespSucceeded          ResponseCode = 0x00
	RespServerFailure      ResponseCode = 0x01
	RespRuleFailure        ResponseCode = 0x02
	RespNetworkUnreachable ResponseCode = 0x03
	RespHostUnreachable    ResponseCode = 0x04
	RespConnectionRefused  ResponseCode = 0x05
	RespTTLExpired         ResponseCode = 0x06
	RespCmdNotSupported    ResponseCode = 0x07
	RespAtypeNotSupported  ResponseCode = 0x08
)

var (
	ErrUnsupportedVer       = errors.New("unsupported socks version")
	ErrUnsupportedCmdVer    = errors.New("unsupported cmd version")
	ErrUnsupportedAuthMetod = errors.New("unsupported auth method")
	ErrUnsupportedCmd       = errors.New("command mode not implemented")
	ErrNoSupportedAuth      = errors.New("no supported authentication methods")
)

type ResponseCode uint8

/*
	    Clients Negotiation:
	    +----+----------+----------+
		|VER | NMETHODS | METHODS  |
	    +----+----------+----------+
	    | 1  |    1     | 1 to 255 |
	    +----+----------+----------+
*/
type HelloMsg struct {
	Ver      byte
	Nmethods byte
	Methods  []byte
}

/*
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
*/

type AuthMsg struct {
	Ver  byte
	ULen byte
	User string
	PLen byte
	Pass string
}

func (a *AuthMsg) String() string {
	return fmt.Sprintf("User: %s Pass: %s", string(a.User), string(a.Pass))
}

/*
	+----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/

type Request struct {
	Ver        byte
	Cmd        byte
	Rsv        byte
	Atype      byte
	DstAddr    net.IP
	DstDN      string
	DstPort    uint16
	ClientAddr net.IP
	ClientPort uint16
	Conn       net.Conn
}

type Reply struct {
	Ver     byte
	Rep     byte
	Rsv     byte
	Atype   byte
	DstAddr net.IP
	DstDN   string
	DstPort uint16
}

func (r *Request) String() string {
	return fmt.Sprintf("Ver: %v Cmd: %v Atype: %v DstAddr: %v DstDN: %v DstPort: %v	Client addr: %v:%v",
		r.Ver, r.Cmd, r.Atype, r.DstAddr, r.DstDN, r.DstPort, r.ClientAddr, r.ClientPort)
}

func (r *Request) GetDstAddres() string {
	return fmt.Sprintf(r.DstAddr.String() + ":" + strconv.FormatUint(uint64(r.DstPort), 10))
}

func (s *Server) auth(r io.Reader, w io.Writer) error {
	buf := make([]byte, 2)
	hlmsg := &HelloMsg{}
	if _, err := r.Read(buf); err != nil {
		log.Printf("Failed to get data %v", err)
		return err
	}
	hlmsg.Ver = buf[0]
	hlmsg.Nmethods = buf[1]
	hlmsg.Methods = make([]byte, hlmsg.Nmethods)

	if hlmsg.Ver != socks5Version {
		return ErrUnsupportedVer
	}

	if _, err := io.ReadAtLeast(r, hlmsg.Methods, int(hlmsg.Nmethods)); err != nil {
		return err
	}

	for _, method := range hlmsg.Methods {
		if method == s.AuthMethod {
			return s.AuthFunc.Authenticate(r, w)
		}
	}
	w.Write([]byte{socks5Version, AuthNoAcceptable})
	return ErrNoSupportedAuth
}

func NewRequest(r io.Reader) (*Request, error) {

	header := make([]byte, 4)
	if _, err := io.ReadAtLeast(r, header, 4); err != nil {
		return nil, err
	}

	rqmsg := &Request{
		Ver:   header[0],
		Cmd:   header[1],
		Rsv:   header[2],
		Atype: header[3],
	}

	if uint8(rqmsg.Ver) != socks5Version {
		return nil, ErrUnsupportedCmdVer
	}

	switch rqmsg.Atype {
	case AtypeIP4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		rqmsg.DstAddr = net.IP(addr)
	case AtypeDN:
		addrlen := make([]byte, 1)
		if _, err := r.Read(addrlen); err != nil {
			return nil, err
		}
		addr := make([]byte, addrlen[0])
		if _, err := io.ReadAtLeast(r, addr, int(addrlen[0])); err != nil {
			return nil, err
		}
		rqmsg.DstDN = string(addr)
		//ctx := context.Background()
		resolvedAddr, err := net.ResolveIPAddr("ip", rqmsg.DstDN)
		if err != nil {
			return nil, err
		}
		rqmsg.DstAddr = resolvedAddr.IP
		//Resolve(ctx, dest.FQDN)
	case AtypeIP6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		rqmsg.DstAddr = net.IP(addr)
	}

	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	rqmsg.DstPort = (uint16(port[0]) << 8) | uint16(port[1])
	return rqmsg, nil
}

func (s *Server) HandleConnect(ctx context.Context, req *Request) error {
	var resp ResponseCode
	dstConn, err := net.DialTimeout("tcp", req.GetDstAddres(), 5*time.Second)
	switch {
	case err == nil:
		resp = RespSucceeded
	case os.IsTimeout(err):
		resp = RespTTLExpired
		return err
	case errors.Is(err, syscall.ECONNREFUSED):
		resp = RespConnectionRefused
		return err
	default:
		resp = RespServerFailure
		return err
	}
	defer dstConn.Close()

	lAddr, lPort := dstConn.LocalAddr().(*net.TCPAddr).IP, dstConn.LocalAddr().(*net.TCPAddr).Port
	// bndAddr is ATYPE + PORT in network byte order
	bndAddr := make([]byte, len(lAddr))
	copy(bndAddr[:], lAddr)
	bndAddr = append(bndAddr, byte(lPort>>8), byte(lPort))

	req.Reply(resp, bndAddr)

	err = proxy(dstConn, req.Conn)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (req *Request) Reply(rc ResponseCode, p []byte) error {
	msg := make([]byte, 4)

	msg[0] = socks5Version
	msg[1] = byte(rc)
	msg[2] = 0x00 // RSV
	msg[3] = 1    // we always bind to ipv4
	msg = append(msg, p...)
	if _, err := req.Conn.Write(msg); err != nil {
		return err
	}
	return nil
}

// proxy is used to copy data from src to destination, and sends errors
// dst is serv src is client
func proxy(dst io.ReadWriter, src io.ReadWriter) error {
	defer dst.(*net.TCPConn).Close()

	go io.Copy(src, dst)
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	return nil
}
