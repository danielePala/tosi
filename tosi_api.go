package tosi

import (
	"net"
	"strconv"
	"fmt"
	"time"
)

const (
	RFC1006port = 102
)

// TosiConn is an implementation of the Conn interface 
// for Tosi network connections. 
type TosiConn struct {
	tcpConn net.TCPConn
}

// DialTosi connects to the remote address raddr on the network net, which must 
// be "tosi", "tosi4", or "tosi6". 
// If laddr is not nil, it is used as the local address for the connection.
func DialTosi(tnet string, laddr, raddr *TosiAddr) (*TosiConn, error) {
	TCPnet := tosiToTCPnet(tnet)
	TCPraddr := tosiToTCPaddr(*raddr)
	tcp, err := net.DialTCP(TCPnet, nil, &TCPraddr)
	if err != nil {
		return nil, err
	}
        _, err = tcp.Write(TPKT(CR(0,0,0)))
        // try to read a TPKT header
	buf := make([]byte, TpktHlen)
	_, err = tcp.Read(buf)
        isTpkt, tlen := IsTPKT(buf)
        if isTpkt && err == nil {
                fmt.Printf("got a TPKT with len %v\n", tlen)
                tlen = tlen - TpktHlen
                // try to read a CC
                buf = make([]byte, tlen)
		_, err = tcp.Read(buf)
                isCC, tlen := IsCC(buf)
                if isCC && err == nil {
                        fmt.Printf("got a CC with len %v, connection established\n", tlen)
			return &TosiConn{*tcp}, nil
                }
        }
	return nil, err
}

func tosiToTCPnet(tosi string) (tcp string) {
	switch tosi {
	case "tosi":
		tcp = "tcp"
	case "tosi4":
		tcp = "tcp4"
	case "tosi6":
		tcp = "tcp6"
	default:
		tcp = ""
	}
	return
} 

func tosiToTCPaddr(tosi TosiAddr) (tcp net.TCPAddr) {
	tcp = net.TCPAddr{tosi.IP, RFC1006port}
	return
}

// Close closes the Tosi connection.
// This is the 'implicit' variant defined in ISO 8073, i.e.
// all it does is closing the underlying TCP connection 
func (c *TosiConn) Close() error {
	return c.tcpConn.Close()
}

// LocalAddr returns the local network address
func (c *TosiConn) LocalAddr() net.Addr {
	return nil
}

// Read implements the Conn Read method. 
func (c *TosiConn) Read(b []byte) (n int, err error) {
	// try to read a TPKT header  
	buf := make([]byte, TpktHlen)
        _, err = c.tcpConn.Read(buf)
        isTpkt, tlen := IsTPKT(buf)
        if isTpkt && err == nil {
                fmt.Printf("got a TPKT with len %v\n", tlen)
                tlen = tlen - TpktHlen
                // try to read a DT 
		buf = make([]byte, tlen)
                _, err = c.tcpConn.Read(buf)
                isDT, tlen := IsDT(buf)
                if isDT && err == nil {
                        fmt.Printf("Got a DT with len %v\n", tlen)
			n = int(tlen)
			copy(b, buf[DTMinLen:])
			return
		}
	}
	return 0, err 
}

// RemoteAddr returns the remote network address
func (c *TosiConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline implements the Conn SetDeadline method. 
func (c *TosiConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *TosiConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method. 
func (c *TosiConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Write implements the Conn Write method. 
func (c *TosiConn) Write(b []byte) (n int, err error) {
	return c.tcpConn.Write(TPKT(DT(b)))
}

// TosiAddr represents the address of a Tosi end point. 
type TosiAddr struct {
	IP net.IP
	Tsel int
}

func (a *TosiAddr) Network() string {
	return "tosi"
}

func (a *TosiAddr) String() string {
	return a.IP.String() + ":" + strconv.Itoa(a.Tsel)
}
 
// ResolveTosiAddr parses addr as a Tosi address of the form host:tsel and 
// resolves domain names to numeric addresses on the network net, 
// which must be "tosi", "tosi4" or "tosi6". 
// A literal IPv6 host address must be enclosed in square brackets, as in "[::]:80". 
func ResolveTosiAddr(tnet, addr string) (tosiAddr *TosiAddr, err error) {
	host, tsel, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	service := host + ":" + strconv.Itoa(RFC1006port)
	tcpNet := tosiToTCPnet(tnet)
	tcpAddr, err := net.ResolveTCPAddr(tcpNet, service)
	if err != nil {
                return
        }
	tselNum, err := strconv.Atoi(tsel)
	return &TosiAddr{tcpAddr.IP, tselNum}, err
}

// TosiListener is a Tosi network listener. Clients should typically use 
// variables of type Listener instead of assuming Tosi. 
type TosiListener struct {
	addr *TosiAddr
	tcpListener net.TCPListener
}

// Accept implements the Accept method in the Listener interface; 
// it waits for the next call and returns a generic Conn. 
func (l *TosiListener) Accept() (c net.Conn, err error) {
	tcp, err := l.tcpListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
        // try to read a TPKT header  
	buf := make([]byte, TpktHlen)
        _, err = tcp.Read(buf)
        isTpkt, tlen := IsTPKT(buf)
        if isTpkt && err == nil {
                fmt.Printf("got a TPKT with len %v\n", tlen)
                tlen = tlen - TpktHlen
                // try to read a CR 
		buf = make([]byte, tlen)
                _, err = tcp.Read(buf)
                isCR, tlen := IsCR(buf)
                if isCR && err == nil {
                        fmt.Printf("got a CR with len %v, sending CC\n", tlen)
			// reply with a CC
                        tpkt := TPKT(CC())
                        tcp.Write(tpkt)
                }
        }
	if err != nil {
		return nil, err
	}
	return &TosiConn{*tcp}, nil
}

// Close stops listening on the Tosi address.
// Already Accepted connections are not closed.
func (l *TosiListener) Close() error {
	return l.tcpListener.Close()
}

// Addr returns the listener's network address
func (l *TosiListener) Addr() net.Addr {
	return l.addr
}

// ListenTosi announces on the Tosi address laddr and returns a Tosi listener. 
// tnet must be "tosi", "tosi4", or "tosi6".  
func ListenTosi(tnet string, laddr *TosiAddr) (*TosiListener, error) {
	tcpAddr := net.TCPAddr{laddr.IP, RFC1006port}
	var tcpNet string
	switch tnet {
        case "tosi":
                tcpNet = "tcp"
        case "tosi4":
                tcpNet = "tcp4"
        case "tosi6":
                tcpNet = "tcp6"
        }
	listener, err := net.ListenTCP(tcpNet, &tcpAddr)
	if err != nil {
		return nil, err
	}
	return &TosiListener{laddr, *listener}, nil
}