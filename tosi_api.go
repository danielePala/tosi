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
	"errors"
	"net"
	"strconv"
	"time"
)

const (
	rfc1006port = 102
)

// TOSIConn is an implementation of the net.Conn interface 
// for TOSI network connections. 
type TOSIConn struct {
	tcpConn                     net.TCPConn // TCP connection
	laddr, raddr                TOSIAddr    // local and remote address
	maxTpduSize                 uint64      // max TPDU size
	srcRef, dstRef              [2]byte     // connection identifiers
	userData                                // read buffer
	readDeadline, writeDeadline time.Time   // read and write deadlines
	useExpedited                bool        // use of expedited TPDUs is enabled 
}

// structure holding data from TCP which hasn't been returned to the user yet
type userData struct {
	readBuf   []byte // read buffer
	expedited bool   // is this data from an expedited TPDU?
}

// DialTOSI connects to the remote address raddr on the network net, which must 
// be "tosi", "tosi4", or "tosi6". 
// If laddr is not nil, it is used as the local address for the connection.
func DialTOSI(tnet string, laddr, raddr *TOSIAddr) (*TOSIConn, error) {
	// setup ISO connection vars 
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01} // random non-zero value
	if laddr != nil {
		cv.locTsel = laddr.Tsel
	}
	cv.remTsel = raddr.Tsel
	return dial(tnet, laddr, raddr, cv)
}

// DialExpeditedTOSI is the same as DialTOSI, but it also negotiates the use of 
// expedited TPDUs during connection establishment.
// The result of the negotiation is returned to the caller.
func DialExpeditedTOSI(tnet string, laddr, raddr *TOSIAddr) (*TOSIConn, error, bool) {
	// setup ISO connection vars 
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01} // random non-zero value
	if laddr != nil {
		cv.locTsel = laddr.Tsel
	}
	cv.remTsel = raddr.Tsel
	cv.options = 0x01
	conn, err := dial(tnet, laddr, raddr, cv)
	if conn != nil {
		return conn, err, conn.useExpedited
	}
	return conn, err, false
}

// dial connects to the remote address raddr on the network net, which must 
// be "tosi", "tosi4", or "tosi6". 
// If laddr is not nil, it is used as the local address for the connection.
// The parameters of the connection request are taken as inputs from the caller. 
func dial(tnet string, laddr, raddr *TOSIAddr, cv connVars) (*TOSIConn, error) {
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
	// send a CR
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
		tpdu := make([]byte, tlen-tpktHlen)
		_, err = tcp.Read(tpdu)
		if err != nil {
			return nil, err
		}
		isCC, errIdx := isCC(tpdu)
		if isCC {
			return handleCc(tpdu, tcp, laddr, raddr, cv)
		}
		err = handleDialError(tpdu, tcp, cv, errIdx)
	}
	tcp.Close()
	return nil, err
}

// parse a CC, handling errors
func handleCc(tpdu []byte, tcp *net.TCPConn, laddr, raddr *TOSIAddr, cv connVars) (*TOSIConn, error) {
	// we have a CC, check if it is valid
	repCv := getConnVars(tpdu)
	valid, erBuf := validateCc(tpdu, cv)
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
		laddr = &TOSIAddr{tcpAddr.IP, nil}
	}
	// determine the max TPDU size
	maxTpduSize, _ := getMaxTpduSize(cv)
	ccSize, noPref := getMaxTpduSize(repCv)
	if !noPref {
		maxTpduSize = ccSize
	}
	return &TOSIConn{
		tcpConn:      *tcp,
		laddr:        *laddr,
		raddr:        *raddr,
		maxTpduSize:  maxTpduSize,
		srcRef:       cv.srcRef,
		dstRef:       repCv.srcRef,
		useExpedited: repCv.options > 0}, nil
}

// handle a tpdu which was expected to be a CC, but it's not 
func handleDialError(tpdu []byte, tcp *net.TCPConn, cv connVars, errIdx uint8) (err error) {
	// no CC received, maybe it's an ER or DR
	isER, _ := isER(tpdu)
	if isER {
		err = getERerror(tpdu)
	}
	isDR, _ := isDR(tpdu)
	if isDR {
		err = getDRerror(tpdu)
	}
	// unknown TPDU
	if (!isDR) && (!isER) {
		reply := tpkt(er(cv.srcRef[:], erParamVal, tpdu[:errIdx]))
		tcp.Write(reply)
		err = errors.New("unknown reply from server")
	}
	return
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
func tosiToTCPaddr(tosi TOSIAddr) (tcp net.TCPAddr) {
	tcp = net.TCPAddr{tosi.IP, rfc1006port}
	return
}

// Close closes the TOSI connection.
// This is the 'implicit' variant defined in ISO 8073, i.e.
// all it does is closing the underlying TCP connection.
func (c *TOSIConn) Close() error {
	return c.tcpConn.Close()
}

// LocalAddr returns the local network address.
func (c *TOSIConn) LocalAddr() net.Addr {
	return &c.laddr
}

// Read implements the net.Conn Read method.
// If b is not large enough for the TPDU data, it fills b and next Read
// will read the rest of the TPDU data. 
func (c *TOSIConn) Read(b []byte) (n int, err error) {
	n, err, _ = c.ReadTOSI(b)
	return
}

// ReadTOSI is the same as Read, but it also indicates if the data comes 
// from an expedited TPDU. 
func (c *TOSIConn) ReadTOSI(b []byte) (n int, err error, expedited bool) {
	if b == nil {
		return 0, errors.New("invalid input"), false
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
		return n, nil, c.expedited
	}
	// read buffer empty, try to read a TPKT header  
	buf := make([]byte, tpktHlen)
	_, err = c.tcpConn.Read(buf)
	isTpkt, tlen := isTPKT(buf)
	if isTpkt && err == nil {
		// try to read a DT (or ED) 
		tpdu := make([]byte, tlen-tpktHlen)
		_, err = c.tcpConn.Read(tpdu)
		if err != nil {
			return 0, err, false
		}
		isDT, errIdx := isDT(tpdu)
		isED, _ := isED(tpdu)
		if isDT {
			n, err = c.handleDt(b, tpdu)
			return n, err, false
		}
		if isED && c.useExpedited {
			n, err = c.handleEd(b, tpdu)
			return n, err, true
		}
		err = c.handleDataError(tpdu, errIdx)
	}
	return 0, err, false
}

// parse an ED, handling errors and buffering issues 
func (c *TOSIConn) handleEd(b, tpdu []byte) (n int, err error) {
	valid, erBuf := validateEd(tpdu)
	if !valid {
		// we got an invalid ED
		// reply with an ER 
		reply := tpkt(er(c.dstRef[:], erParamVal, erBuf))
		c.tcpConn.SetWriteDeadline(c.readDeadline)
		c.tcpConn.Write(reply)
		c.tcpConn.SetWriteDeadline(c.writeDeadline)
		return 0, errors.New("received an invalid ED")
	}
	c.expedited = true
	return c.handleData(b, tpdu)
}

// parse a DT, handling errors and buffering issues 
func (c *TOSIConn) handleDt(b, tpdu []byte) (n int, err error) {
	valid, erBuf := validateDt(tpdu, c.maxTpduSize)
	if !valid {
		// we got an invalid DT
		// reply with an ER 
		reply := tpkt(er(c.dstRef[:], erParamVal, erBuf))
		c.tcpConn.SetWriteDeadline(c.readDeadline)
		c.tcpConn.Write(reply)
		c.tcpConn.SetWriteDeadline(c.writeDeadline)
		return 0, errors.New("received an invalid DT")
	}
	c.expedited = false
	return c.handleData(b, tpdu)
}

// parse a DT or ED, handling buffering issues 
func (c *TOSIConn) handleData(b, tpdu []byte) (n int, err error) {
	sduLen := len(tpdu) - dtMinLen
	copy(b, tpdu[dtMinLen:])
	if len(b) < sduLen {
		// Cannot return the whole SDU, save to buffer
		uncopiedLen := sduLen - len(b)
		uncopiedIdx := dtMinLen + len(b)
		c.readBuf = make([]byte, uncopiedLen)
		copy(c.readBuf, tpdu[uncopiedIdx:])
		n = len(b)
	} else {
		c.readBuf = nil
		n = sduLen
	}
	return
}

// handle a tpdu which was expected to be a DT or ED, but it's not 
func (c *TOSIConn) handleDataError(tpdu []byte, errIdx uint8) (err error) {
	// no DT or ED received, maybe it's an ER or DR
	isER, _ := isER(tpdu)
	if isER {
		err = getERerror(tpdu)
	}
	isDR, _ := isDR(tpdu)
	if isDR {
		err = getDRerror(tpdu)
	}
	if (isDR) || (isER) {
		c.Close()
	} else {
		reply := tpkt(er(c.dstRef[:], erParamVal, tpdu[:errIdx]))
		c.tcpConn.SetWriteDeadline(c.readDeadline)
		c.tcpConn.Write(reply)
		c.tcpConn.SetWriteDeadline(c.writeDeadline)
		err = errors.New("received an invalid TPDU")
	}
	return
}

// RemoteAddr returns the remote network address.
func (c *TOSIConn) RemoteAddr() net.Addr {
	return &c.raddr
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *TOSIConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *TOSIConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *TOSIConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.tcpConn.SetWriteDeadline(t)
}

// Write implements the net.Conn Write method.
func (c *TOSIConn) Write(b []byte) (n int, err error) {
	return c.writeTpdu(b, dt, c.maxTpduSize-dtMinLen)
}

// WriteTOSI is the same as Write, but it also allows to send expedited TPDUs. 
// If the use of expedited TPDUs was not negotiated during connection 
// establishment, the expedited parameter is ignored.
func (c *TOSIConn) WriteTOSI(b []byte, expedited bool) (n int, err error) {
	if (expedited == false) || (c.useExpedited == false) {
		return c.writeTpdu(b, dt, c.maxTpduSize-dtMinLen)
	}
	return c.writeTpdu(b, ed, edMaxLen-edMinLen)
}

// write data using the TPDU type implemented by the tpdu argument
func (c *TOSIConn) writeTpdu(b []byte, tpdu func([]byte) []byte, maxSduSize uint64) (n int, err error) {
	if b == nil {
		return 0, errors.New("invalid input")
	}
	bufLen := uint64(len(b))
	// if b is too big, split it into smaller chunks
	if bufLen > maxSduSize {
		numWrites := (bufLen / maxSduSize) + 1
		var i uint64
		for i = 0; i < numWrites; i++ {
			start := maxSduSize * i
			end := maxSduSize * (i + 1)
			if end > bufLen {
				end = bufLen
			}
			part := tpkt(tpdu(b[start:end]))
			nPart, err := c.tcpConn.Write(part)
			n = n + nPart
			if err != nil {
				return n, err
			}
		}
		return
	}
	return c.tcpConn.Write(tpkt(tpdu(b)))
}

// TOSIAddr represents the address of a TOSI end point. 
type TOSIAddr struct {
	IP   net.IP
	Tsel []byte
}

// Network returns the address's network name, "tosi".
func (a *TOSIAddr) Network() string {
	return "tosi"
}

func (a *TOSIAddr) String() string {
	if a.Tsel != nil {
		return a.IP.String() + ":" + string(a.Tsel)
	}
	return a.IP.String()
}

// ResolveTOSIAddr parses addr as a TOSI address of the form host:tsel and 
// resolves domain names to numeric addresses on the network net, 
// which must be "tosi", "tosi4" or "tosi6". 
// A literal IPv6 host address must be enclosed in square brackets, as in "[::]:80".
// tsel is the "trasport selector", which can be an arbitrary sequence
// of bytes. Thus '10.20.30.40:hello' is a valid address.  
func ResolveTOSIAddr(tnet, addr string) (tosiAddr *TOSIAddr, err error) {
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
		return &TOSIAddr{tcpAddr.IP, []byte(tsel)}, nil
	}
	return &TOSIAddr{tcpAddr.IP, nil}, nil
}

// TOSIListener is a TOSI network listener. Clients should typically use 
// variables of type net.Listener instead of assuming TOSI. 
type TOSIListener struct {
	addr        *TOSIAddr
	tcpListener net.TCPListener
}

// Accept implements the Accept method in the net.Listener interface; 
// it waits for the next call and returns a generic net.Conn. 
func (l *TOSIListener) Accept() (c net.Conn, err error) {
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
		buf = make([]byte, tlen-tpktHlen)
		_, err = tcp.Read(buf)
		isCR, tlen := isCR(buf)
		if isCR && err == nil {
			return l.handleCr(buf, tcp)
		}
		if err == nil {
			// reply with an ER
			zeroDstRef := []byte{0x00, 0x00}
			reply = tpkt(er(zeroDstRef, erParamVal, buf[:tlen]))
			_, err = tcp.Write(reply)
		}
	}
	tcp.Close()
	return nil, err
}

// AcceptTOSI is the same as Accept, but it also indicates if the use of 
// expedited TPDUs was negotiated during connection establishment.
func (l *TOSIListener) AcceptTOSI() (c net.Conn, err error, expedited bool) {
	c, err = l.Accept()
	if c != nil {
		return c, err, c.(*TOSIConn).useExpedited
	}
	return c, err, false
}

// parse a CR, handling errors
func (l *TOSIListener) handleCr(tpdu []byte, tcp *net.TCPConn) (c net.Conn, err error) {
	var reply []byte
	var repCv connVars
	cv := getConnVars(tpdu)
	valid, erBuf := validateCr(tpdu, l.addr.Tsel)
	if valid {
		// reply with a CC
		repCv.locTsel = cv.locTsel
		repCv.remTsel = l.addr.Tsel
		repCv.tpduSize = cv.tpduSize
		repCv.prefTpduSize = cv.prefTpduSize
		repCv.srcRef = [2]byte{0x02, 0x02} // random non-zero value
		repCv.dstRef = cv.srcRef
		repCv.options = cv.options
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
		raddr := TOSIAddr{tcpAddr.IP, cv.locTsel}
		// determine the max TPDU size
		maxTpduSize, _ := getMaxTpduSize(cv)
		return &TOSIConn{
			tcpConn:      *tcp,
			laddr:        *l.addr,
			raddr:        raddr,
			maxTpduSize:  maxTpduSize,
			srcRef:       repCv.srcRef,
			dstRef:       cv.srcRef,
			useExpedited: cv.options > 0}, nil
	}
	tcp.Close()
	if err == nil {
		err = errors.New("received an invalid CR")
	}
	return nil, err
}

// Close stops listening on the TOSI address.
// Already Accepted connections are not closed.
func (l *TOSIListener) Close() error {
	return l.tcpListener.Close()
}

// Addr returns the listener's network address.
func (l *TOSIListener) Addr() net.Addr {
	return l.addr
}

// ListenTOSI announces on the TOSI address laddr and returns a TOSI listener. 
// tnet must be "tosi", "tosi4", or "tosi6".  
func ListenTOSI(tnet string, laddr *TOSIAddr) (*TOSIListener, error) {
	tcpAddr := tosiToTCPaddr(*laddr)
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
		return nil, errors.New("invalid network")
	}
	listener, err := net.ListenTCP(tcpNet, &tcpAddr)
	if err != nil {
		return nil, err
	}
	return &TOSIListener{laddr, *listener}, nil
}
