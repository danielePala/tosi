/* 
 Copyright 2013 Daniele Pala <pala.daniele@gmail.com>

 This file is part of tosi.

 tosi is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 tosi is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with tosi.  If not, see <http://www.gnu.org/licenses/>.

*/

package tosi

import (
	"net"
	"strconv"
	"time"
	"errors"
)

const (
	rfc1006port = 102
)

// TosiConn is an implementation of the Conn interface 
// for Tosi network connections. 
type TosiConn struct {
	tcpConn net.TCPConn    // TCP connection
	laddr, raddr TosiAddr  // local and remote address
	maxTpduSize uint64     // max TPDU size
	srcRef, dstRef [2]byte // connection identifiers
	readBuf []byte         // read buffer
}

// DialTosi connects to the remote address raddr on the network net, which must 
// be "tosi", "tosi4", or "tosi6". 
// If laddr is not nil, it is used as the local address for the connection.
func DialTosi(tnet string, laddr, raddr *TosiAddr) (*TosiConn, error) {
	TCPnet := tosiToTCPnet(tnet)
	if TCPnet == "" {
		return nil, errors.New("invalid network")
	}
	TCPraddr := tosiToTCPaddr(*raddr)
	// try to establish a TCP connection
	tcp, err := net.DialTCP(TCPnet, nil, &TCPraddr)
	if err != nil {
		return nil, err
	}
	// setup ISO connection vars and send a CR
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01} // random non-zero value
	if laddr != nil {
		cv.locTsel = laddr.Tsel
	}
	cv.remTsel = raddr.Tsel
        _, err = tcp.Write(tpkt(cr(cv)))
	if err != nil {
		return nil, err
	}
        // try to read a TPKT header as response
	buf := make([]byte, tpktHlen)
	_, err = tcp.Read(buf)
        isTpkt, tlen := isTPKT(buf)
        if isTpkt && err == nil {
                // try to read a CC
                buf = make([]byte, tlen - tpktHlen)
		_, err = tcp.Read(buf)
                isCC, tlen := isCC(buf)
                if isCC && err == nil {
                        // we have a CC, check if it is valid
			repCv := getConnVars(buf)
			valid, erBuf := validateCc(buf, cv, repCv)
			if !valid {
				// we got an invalid CC
				// reply with an ER and refuse the connection
                                reply := tpkt(er(cv.srcRef[:], erParamVal, erBuf))
				tcp.Write(reply)
				tcp.Close()
				return nil, errors.New("received an invalid CC")
			}
			// all ok, connection established
			if laddr == nil {
				var tcpAddr *net.TCPAddr
				tcpAddr = tcp.LocalAddr().(*net.TCPAddr)
				laddr = &TosiAddr{tcpAddr.IP, nil}
			}
			// determine the max TPDU size
			maxTpduSize, _ := getMaxTpduSize(cv)
                        ccSize, noPref := getMaxTpduSize(repCv)
			if !noPref {
				maxTpduSize = ccSize
			}
			return &TosiConn{tcpConn: *tcp, 
				         laddr: *laddr, 
				         raddr: *raddr, 
				         maxTpduSize: maxTpduSize, 
				         srcRef: cv.srcRef, 
			                 dstRef: repCv.srcRef}, nil
                } else {
			// no CC received, maybe it's an ER or DR
			isER, _ := isER(buf)
			if isER {
				err = getERerror(buf)
			}
			isDR, _ := isDR(buf)
                        if isDR {
				err = getDRerror(buf)
			}
			// unknown TPDU
			if (!isDR) && (!isER) && (err == nil) {
				reply := tpkt(er(cv.srcRef[:], erParamVal, buf[:tlen]))
				tcp.Write(reply)
				err = errors.New("unknown reply from server")
			}
		}
        }
	tcp.Close()
	return nil, err
}

// convert a tosi net to a TCP net
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

// convert a tosi addr to a TCP addr
func tosiToTCPaddr(tosi TosiAddr) (tcp net.TCPAddr) {
	tcp = net.TCPAddr{tosi.IP, rfc1006port}
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
	return &c.laddr
}

// Read implements the Conn Read method.
// If b is not large enough for the TPDU data, it fills b and next Read
// will read the rest of the TPDU data. 
func (c *TosiConn) Read(b []byte) (n int, err error) {
	if b == nil {
		return 0, errors.New("invalid input")
	}
	// see if there's something in the read buffer
	if c.readBuf != nil {
		copy(b, c.readBuf)
		if len(b) < len(c.readBuf) {
			// Cannot return the whole SDU
			n = len(b)
			c.readBuf = c.readBuf[len(b):]
		} else {
			n = len(c.readBuf)
			c.readBuf = nil
		}
		return n, nil
	} 
	// read buffer empty, try to read a TPKT header  
	buf := make([]byte, tpktHlen)
	_, err = c.tcpConn.Read(buf)
	isTpkt, tlen := isTPKT(buf)
	if isTpkt && err == nil {
		// try to read a DT 
		buf = make([]byte, tlen - tpktHlen)
		_, err = c.tcpConn.Read(buf)
		isDT, idx := isDT(buf)
		if isDT && err == nil {
			valid, erBuf := validateDt(buf)
			if !valid {
				// we got an invalid DT
				// reply with an ER 
                                reply := tpkt(er(c.dstRef[:], erParamVal, erBuf))
				c.tcpConn.Write(reply)
				return 0, errors.New("received an invalid DT")
			}
			sduLen := len(buf) - dtMinLen
			copy(b, buf[dtMinLen:])
			if len(b) < sduLen {
				// Cannot return the whole SDU, save to buffer
				uncopiedLen := sduLen - len(b)  
				uncopiedIdx := dtMinLen + len(b)
				c.readBuf = make([]byte, uncopiedLen)
				copy(c.readBuf, buf[uncopiedIdx:])
				n = len(b)
			} else {
				c.readBuf = nil
				n = sduLen
			}
			return
		} else {
			if err != nil {
				return 0, err
			}
			// no DT received, maybe it's an ER or DR
			isER, _ := isER(buf)
			if isER {
				err = getERerror(buf)
			}
			isDR, _ := isDR(buf)
                        if isDR {
				err = getDRerror(buf)
			}
			if (isDR) || (isER) {
				c.Close()
			} else {
				reply := tpkt(er(c.dstRef[:], erParamVal, buf[:idx]))
				c.tcpConn.Write(reply)
				err = errors.New("received an invalid TPDU")
			}
		}
	}
	return 0, err 
}

// RemoteAddr returns the remote network address
func (c *TosiConn) RemoteAddr() net.Addr {
	return &c.raddr
}

// SetDeadline implements the Conn SetDeadline method. 
func (c *TosiConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *TosiConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method. 
func (c *TosiConn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

// Write implements the Conn Write method. 
func (c *TosiConn) Write(b []byte) (n int, err error) {
	if b == nil {
		return 0, errors.New("invalid input")
	}
	maxSduSize := c.maxTpduSize - dtMinLen
	bufLen := uint64(len(b))
	// if b is too big, split it into smaller chunks
	if bufLen > maxSduSize {
		numWrites := (bufLen/maxSduSize) + 1
		var i uint64
		for i=0; i<numWrites; i++ {
			start := maxSduSize * i
			end := maxSduSize * (i + 1) 
			if end > bufLen {
				end = bufLen
			}
			nPart, err := c.tcpConn.Write(tpkt(dt(b[start:end])))
			n = n + nPart
			if err != nil {
				return n, err
			}
		}
		return
	}
	return c.tcpConn.Write(tpkt(dt(b)))
}

// TosiAddr represents the address of a Tosi end point. 
type TosiAddr struct {
	IP net.IP
	Tsel []byte
}

func (a *TosiAddr) Network() string {
	return "tosi"
}

func (a *TosiAddr) String() string {
	return a.IP.String() + ":" + string(a.Tsel)
}
 
// ResolveTosiAddr parses addr as a Tosi address of the form host:tsel and 
// resolves domain names to numeric addresses on the network net, 
// which must be "tosi", "tosi4" or "tosi6". 
// A literal IPv6 host address must be enclosed in square brackets, as in "[::]:80". 
func ResolveTosiAddr(tnet, addr string) (tosiAddr *TosiAddr, err error) {
	host, tsel, err := net.SplitHostPort(addr)
	if err != nil {
		// maybe no port was given, try to parse a plain IP address
		ip := net.ParseIP(addr)
		if ip == nil {
			return
		}
		host = ip.String()
		tsel = ""
	}
	service := host + ":" + strconv.Itoa(rfc1006port)
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
		return nil, errors.New("invalid network")
	}
	tcpAddr, err := net.ResolveTCPAddr(tcpNet, service)
	if err != nil {
                return
        }
	if tsel != "" {
		return &TosiAddr{tcpAddr.IP, []byte(tsel)}, nil
	} 
	return &TosiAddr{tcpAddr.IP, nil}, nil
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
	// listen for TCP connections
	tcp, err := l.tcpListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
        // try to read a TPKT header  
	buf := make([]byte, tpktHlen)
        _, err = tcp.Read(buf)
        isTpkt, tlen := isTPKT(buf)
        if isTpkt && err == nil {
                // try to read a CR 
		var reply []byte
		buf = make([]byte, tlen - tpktHlen)
                _, err = tcp.Read(buf)
                isCR, tlen := isCR(buf)
                if isCR && err == nil {
			cv := getConnVars(buf)
			var repCv connVars
			valid, erBuf := validateCr(buf, l.addr.Tsel)
			if valid {
				// reply with a CC
				repCv.locTsel = cv.locTsel
				repCv.remTsel = l.addr.Tsel
				repCv.tpduSize = cv.tpduSize
				repCv.prefTpduSize = cv.prefTpduSize
				repCv.srcRef = [2]byte{0x02, 0x02} // random non-zero value
				repCv.dstRef = cv.srcRef
				reply = tpkt(cc(repCv))
			} else {
				// reply with an ER
                                reply = tpkt(er(cv.srcRef[:], erParamVal, erBuf))
			}
			_, err = tcp.Write(reply)
			if valid && (err == nil) {
				// connection established
				// NOTE: in reply to our CC, we may also receive 
				// an ER or DR. We don't check this now, but leave
				// it to the Read function.
				var tcpAddr *net.TCPAddr
				tcpAddr = tcp.RemoteAddr().(*net.TCPAddr)
				raddr := TosiAddr{tcpAddr.IP, cv.locTsel}
				// determine the max TPDU size
				maxTpduSize, _ := getMaxTpduSize(cv)
				return &TosiConn{tcpConn: *tcp, 
				                 laddr: *l.addr, 
				                 raddr: raddr, 
				                 maxTpduSize: maxTpduSize, 
				                 srcRef: repCv.srcRef, 
			                         dstRef: cv.srcRef}, nil
			} else {
				tcp.Close()
				if err == nil {
					err = errors.New("received an invalid CR")
				}
				return nil, err
			}
                } else {
			if err == nil {
				// reply with an ER
				reply = tpkt(er([]byte{0x00, 0x00}, erParamVal, buf[:tlen]))
				_, err = tcp.Write(reply)
			}
		}
        }
	tcp.Close()
	return nil, err
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
	tcpAddr := tosiToTCPaddr(*laddr)
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
                return nil, errors.New("invalid network")
        }
	listener, err := net.ListenTCP(tcpNet, &tcpAddr)
	if err != nil {
		return nil, err
	}
	return &TosiListener{laddr, *listener}, nil
}