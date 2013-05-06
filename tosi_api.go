/*
 Definition of the external interface of the package, based on the
 constructs defined in the standard 'net' package.

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
	rfc1006port = 102 // TCP port used by TOSI servers
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
	UseExpedited                bool        // use of expedited TPDUs enabled
}

// structure holding data from TCP which hasn't been returned to the user yet
type userData struct {
	readBuf   []byte // read buffer
	expedited bool   // is this data from an expedited TPDU?
}

// DialOptions contains options to be used by the DialOptTOSI function during
// connection establishment: use of expedited data transfer and initial user
// data (up to 32 bytes).
type DialOptions struct {
	Expedited bool
	Data      []byte
}

// DialTOSI connects to the remote address raddr on the network net, which must
// be "tosi", "tosi4", or "tosi6".
// If laddr is not nil, it is used as the local address for the connection.
func DialTOSI(tnet string, laddr, raddr *TOSIAddr) (*TOSIConn, error) {
	return DialOptTOSI(tnet, laddr, raddr, DialOptions{})
}

// DialOptTOSI is the same as DialTOSI, but it takes an additional 'options'
// parameter which can be used to negotiate the use of expedited TPDUs and
// to send initial data during connection establishment.
// The result of the expedited data negotiation is returned in a TOSIConn field.
// The maximum size of initial data is 32 bytes, if the input is bigger than
// this size, it is trimmed.
func DialOptTOSI(tnet string, laddr, raddr *TOSIAddr, opt DialOptions) (*TOSIConn, error) {
	if raddr == nil {
		return nil, errors.New("invalid remote address")
	}
	// setup ISO connection vars
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01} // random non-zero value
	if laddr != nil {
		cv.locTsel = laddr.Tsel
	}
	cv.remTsel = raddr.Tsel
	if opt.Expedited {
		cv.options = 0x01
	}
	cv.userData = opt.Data
	if len(cv.userData) > maxDataLen {
		cv.userData = cv.userData[:maxDataLen]
	}
	return dial(tnet, laddr, raddr, cv)
}

// dial connects to the remote address raddr on the network net, which must
// be "tosi", "tosi4", or "tosi6".
// If laddr is not nil, it is used as the local address for the connection.
// The parameters of the connection request are taken as inputs from the caller.
func dial(tnet string, laddr, raddr *TOSIAddr, cv connVars) (*TOSIConn, error) {
	TCPnet := tosiToTCPnet(tnet)
	if TCPnet == "" {
		// this check is needed by Go versions < 1.1
		return nil, errors.New("unknown network")
	}
	TCPraddr := tosiToTCPaddr(*raddr)
	// try to establish a TCP connection
	tcp, err := net.DialTCP(TCPnet, nil, &TCPraddr)
	if err != nil {
		return nil, err
	}
	_, err = writePacket(tcp, tpkt(cr(cv))) // send a CR
	if err != nil {
		return nil, err
	}
	// try to read a TPKT header as response
	buf := make([]byte, tpktHlen)
	_, err = readPacket(tcp, buf)
	isTpkt, tlen := isTPKT(buf)
	if isTpkt && err == nil {
		// try to read a CC
		tpdu := make([]byte, tlen-tpktHlen)
		_, err = readPacket(tcp, tpdu)
		if err != nil {
			return nil, err
		}
		isCC, _ := isCC(tpdu)
		if isCC {
			c, err := handleCc(tpdu, tcp, cv)
			if laddr == nil {
				var tcpAddr = tcp.LocalAddr().(*net.TCPAddr)
				c.laddr = TOSIAddr{IP: tcpAddr.IP, Tsel: nil}
			}
			c.raddr = *raddr
			return c, err
		}
		err = handleDialError(tpdu, cv.srcRef[:], tcp)
	}
	tcp.Close()
	return nil, err
}

// parse a CC, handling errors
func handleCc(tpdu []byte, tcp *net.TCPConn, cv connVars) (*TOSIConn, error) {
	// we have a CC, check if it is valid
	valid, erBuf := validateCc(tpdu, cv)
	if !valid {
		// we got an invalid CC
		// reply with an ER and refuse the connection
		reply := tpkt(er(cv.srcRef[:], erParamVal, erBuf))
		writePacket(tcp, reply)
		tcp.Close()
		return nil, errors.New("received an invalid CC")
	}
	// all ok, connection established
	repCv := getConnVars(tpdu)
	return &TOSIConn{
		tcpConn:      *tcp,
		maxTpduSize:  getMaxTpduSize(repCv),
		srcRef:       cv.srcRef,
		dstRef:       repCv.srcRef,
		userData:     userData{readBuf: repCv.userData},
		UseExpedited: repCv.options > 0}, nil
}

// handle a tpdu which was expected to be a CC, but it's not
func handleDialError(tpdu, srcRef []byte, tcp *net.TCPConn) (err error) {
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
	_, errIdx := isCC(tpdu)
	if (!isDR) && (!isER) {
		reply := tpkt(er(srcRef, erParamVal, tpdu[:errIdx]))
		writePacket(tcp, reply)
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
	tcp = net.TCPAddr{IP: tosi.IP, Port: rfc1006port}
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

// Read from a TCP connection until the input buffer is full.
func readPacket(c *net.TCPConn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Write to a TCP connection a whole input buffer.
func writePacket(c *net.TCPConn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Write(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
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
	_, err = readPacket(&c.tcpConn, buf)
	isTpkt, tlen := isTPKT(buf)
	if isTpkt && err == nil {
		// try to read a DT (or ED)
		tpdu := make([]byte, tlen-tpktHlen)
		_, err = readPacket(&c.tcpConn, tpdu)
		if err != nil {
			return 0, err, false
		}
		isDT, errIdx := isDT(tpdu)
		isED, _ := isED(tpdu)
		if isDT {
			n, err = c.handleDt(b, tpdu)
			return n, err, false
		}
		if isED && c.UseExpedited {
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
		writePacket(&c.tcpConn, reply)
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
		writePacket(&c.tcpConn, reply)
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
		writePacket(&c.tcpConn, reply)
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
	return c.WriteTOSI(b, false)
}

// WriteTOSI is the same as Write, but it also allows to send expedited TPDUs.
// If the use of expedited TPDUs was not negotiated during connection
// establishment, the expedited parameter is ignored.
func (c *TOSIConn) WriteTOSI(b []byte, expedited bool) (n int, err error) {
	if (expedited == false) || (c.UseExpedited == false) {
		return c.writeTpdu(b, dt, c.maxTpduSize-dtMinLen)
	}
	return c.writeTpdu(b, ed, edMaxLen-edMinLen)
}

// write data using the TPDU type implemented by the tpdu argument.
func (c *TOSIConn) writeTpdu(b []byte, tpdu func([]byte, byte) []byte, maxSduSize uint64) (n int, e error) {
	if b == nil {
		return 0, errors.New("invalid input")
	}
	bufLen := uint64(len(b))
	// if b is too big, split it into smaller chunks
	if bufLen > maxSduSize {
		numWrites := (bufLen / maxSduSize)
		if (bufLen % maxSduSize) > 0 {
			numWrites += 1
		}
		var i uint64
		var endOfTsdu byte
		for i = 0; i < numWrites; i++ {
			start := maxSduSize * i
			end := maxSduSize * (i + 1)
			if end > bufLen {
				end = bufLen
			}
			if i == numWrites-1 {
				endOfTsdu = nrEot
			} else {
				endOfTsdu = nrNonEot
			}
			part := tpkt(tpdu(b[start:end], endOfTsdu))
			nPart, err := writePacket(&c.tcpConn, part)
			n = n + nPart
			if err != nil {
				return n, err
			}
		}
		return
	}
	return writePacket(&c.tcpConn, tpkt(tpdu(b, nrEot)))
}

// TOSIAddr represents the address of a TOSI end point.
type TOSIAddr struct {
	IP   net.IP // IP address
	Tsel []byte // Transport selector (optional)
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
// A literal IPv6 host address must be enclosed in square brackets,
// as in "[::]:80". tsel is the "trasport selector", which can be an arbitrary
// sequence of bytes. Thus '10.20.30.40:hello' is a valid address.
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
func (l *TOSIListener) Accept() (net.Conn, error) {
	return l.accept(nil)
}

// AcceptTOSI is the same as Accept, but it also takes a user function which
// should return initial user data to be sent with the CC packet, taking as
// input the CR user data (if present).
func (l *TOSIListener) AcceptTOSI(data func([]byte) []byte) (net.Conn, error) {
	return l.accept(data)
}

// accept is a private function implementing both Accept and AcceptTOSI.
func (l *TOSIListener) accept(data func([]byte) []byte) (net.Conn, error) {
	// listen for TCP connections
	tcp, err := l.tcpListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	// try to read a TPKT header
	buf := make([]byte, tpktHlen)
	_, err = readPacket(tcp, buf)
	isTpkt, tlen := isTPKT(buf)
	if isTpkt && err == nil {
		// try to read a CR
		var reply []byte
		buf = make([]byte, tlen-tpktHlen)
		_, err = readPacket(tcp, buf)
		isCR, tlen := isCR(buf)
		if isCR && err == nil {
			return l.handleCr(buf, tcp, data)
		}
		if err == nil {
			// reply with an ER
			zeroDstRef := []byte{0x00, 0x00}
			reply = tpkt(er(zeroDstRef, erParamVal, buf[:tlen]))
			_, err = writePacket(tcp, reply)
		}
	}
	tcp.Close()
	return nil, err
}

// parse a CR, handling errors and sending a CC in response.
func (l *TOSIListener) handleCr(tpdu []byte, tcp *net.TCPConn, data func([]byte) []byte) (net.Conn, error) {
	var reply []byte
	var repCv connVars
	valid, erBuf := validateCr(tpdu, l.addr.Tsel)
	cv := getConnVars(tpdu)
	if valid {
		// reply with a CC
		repCv.locTsel = cv.locTsel
		repCv.remTsel = l.addr.Tsel
		if cv.prefTpduSize == nil {
			repCv.tpduSize = cv.tpduSize
		}
		repCv.prefTpduSize = cv.prefTpduSize
		repCv.srcRef = [2]byte{0x02, 0x02} // random non-zero value
		repCv.dstRef = cv.srcRef
		repCv.options = cv.options
		if data != nil {
			repCv.userData = data(cv.userData)
		}
		if len(repCv.userData) > maxDataLen {
			repCv.userData = repCv.userData[:maxDataLen]
		}
		reply = tpkt(cc(repCv))
	} else {
		// reply with an ER
		reply = tpkt(er(cv.srcRef[:], erParamVal, erBuf))
	}
	_, err := writePacket(tcp, reply)
	if valid && (err == nil) {
		// connection established
		// NOTE: in reply to our CC, we may also receive
		// an ER or DR. We don't check this now, but leave
		// it to the Read function.
		var tcpAddr *net.TCPAddr
		tcpAddr = tcp.RemoteAddr().(*net.TCPAddr)
		raddr := TOSIAddr{tcpAddr.IP, cv.locTsel}
		return &TOSIConn{
			tcpConn:      *tcp,
			laddr:        *l.addr,
			raddr:        raddr,
			maxTpduSize:  getMaxTpduSize(cv),
			srcRef:       repCv.srcRef,
			dstRef:       cv.srcRef,
			userData:     userData{readBuf: cv.userData},
			UseExpedited: cv.options > 0}, nil
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
	if laddr == nil {
		return nil, errors.New("invalid local address")
	}
	tcpAddr := tosiToTCPaddr(*laddr)
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
		// this check is needed by Go versions < 1.1
		return nil, errors.New("unknown network")
	}
	listener, err := net.ListenTCP(tcpNet, &tcpAddr)
	if err != nil {
		return nil, err
	}
	return &TOSIListener{laddr, *listener}, nil
}
