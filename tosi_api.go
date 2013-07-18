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
	"strings"
	"time"
)

const rfc1006port = "102" // Default TCP port used by TOSI servers

// TOSIConn is an implementation of the net.Conn interface
// for TOSI network connections.
type TOSIConn struct {
	MaxTpduSize    int         // max TPDU size
	UseExpedited   bool        // use of expedited TPDUs enabled
	tcpConn        net.TCPConn // TCP connection
	laddr, raddr   TOSIAddr    // local and remote address
	srcRef, dstRef [2]byte     // connection identifiers
	userData                   // read buffer
}

// structure holding data from TCP which hasn't been returned to the user yet
type userData struct {
	readBuf   []byte // read buffer
	expedited bool   // is this data from an expedited TPDU?
	endOfTSDU bool   // is this data the last part of a TSDU?
}

// DialOpt contains options to be used by the DialOptTOSI function during
// connection establishment: use of expedited data transfer, maximum TPDU
// size and initial user data (up to 32 bytes). The maximum TPDU size should
// be a multiple of 128, and be smaller than 65531 bytes.
type DialOpt struct {
	Expedited   bool   // use of expedited data transfer
	Data        []byte // initial user data
	MaxTPDUSize int    // maximum TPDU size
}

// ReadInfo contains information returned by ReadTOSI regarding the data
// passed to the caller: the number of bytes read, if the data comes
// from an expedited TPDU, and if it is the end of a TSDU.
type ReadInfo struct {
	N         int  // number of bytes read
	Expedited bool // is this data from an expedited TPDU?
	EndOfTSDU bool // is this data the last part of a TSDU?
}

// TOSIAddr represents the address of a TOSI end point.
type TOSIAddr struct {
	net.TCPAddr        // TCP address
	TSel        []byte // Transport selector (optional)
}

// TOSIListener is a TOSI network listener. Clients should typically use
// variables of type net.Listener instead of assuming TOSI.
type TOSIListener struct {
	addr        *TOSIAddr
	tcpListener net.TCPListener
}

// DialTOSI connects to the remote address raddr on the network net, which must
// be "tosi", "tosi4", or "tosi6".
// If loc is not nil, it is used as the local address for the connection.
func DialTOSI(net string, loc, rem *TOSIAddr) (*TOSIConn, error) {
	return DialOptTOSI(net, loc, rem, DialOpt{})
}

// DialOptTOSI is the same as DialTOSI, but it takes an additional 'options'
// parameter which can be used to negotiate the use of expedited TPDUs and
// to send initial data during connection establishment.
// The result of the expedited data negotiation is returned in a TOSIConn field.
// The maximum size of initial data is 32 bytes, if the input is bigger than
// this size, it is trimmed.
func DialOptTOSI(net string, loc, rem *TOSIAddr, op DialOpt) (*TOSIConn, error) {
	if rem == nil {
		return nil, errors.New("invalid remote address")
	}
	// setup ISO connection vars
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01} // random non-zero value
	if loc != nil {
		cv.locTsel = loc.TSel
	}
	cv.remTsel = rem.TSel
	if op.Expedited {
		cv.options = expeditedOpt
	}
	cv.userData = op.Data
	if len(cv.userData) > maxDataLen {
		cv.userData = cv.userData[:maxDataLen]
	}
	if op.MaxTPDUSize > 0 && op.MaxTPDUSize < defTpduSize {
		tpduSizes := map[int]byte{128: 7, 256: 8, 512: 9,
			1024: 10, 2048: 11}
		switch op.MaxTPDUSize {
		case 128, 256, 512, 1024, 2048:
			cv.tpduSize = tpduSizes[op.MaxTPDUSize]
		default:
			cv.tpduSize = tpduSizes[2048]
			cv.prefTpduSize = []byte{byte(op.MaxTPDUSize / 128)}
		}
	}
	return dial(net, loc, rem, cv)
}

// dial connects to the remote address raddr on the network tnet, which must
// be "tosi", "tosi4", or "tosi6".
// If laddr is not nil, it is used as the local address for the connection.
// The parameters of the connection request are taken as inputs from the caller.
func dial(tnet string, laddr, raddr *TOSIAddr, cv connVars) (*TOSIConn, error) {
	TCPnet := tosiToTCPnet(tnet)
	if TCPnet == "" {
		// this check is needed by Go versions < 1.1
		return nil, errors.New("unknown network")
	}
	var tcpLaddr *net.TCPAddr
	if laddr != nil {
		tcpLaddr = &laddr.TCPAddr
	} else {
		tcpLaddr = nil
	}
	// try to establish a TCP connection
	tcp, err := net.DialTCP(TCPnet, tcpLaddr, &raddr.TCPAddr)
	if err != nil {
		return nil, err
	}
	_, err = writePacket(tcp, tpkt(cr(cv))) // send a CR
	if err != nil {
		tcp.Close()
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
			tcp.Close()
			return nil, err
		}
		isCC, _ := isCC(tpdu)
		if isCC {
			c, err := handleCc(tpdu, tcp, cv)
			if err != nil {
				return c, err
			}
			if laddr == nil {
				var tcpAddr = tcp.LocalAddr().(*net.TCPAddr)
				c.laddr.TCPAddr = *tcpAddr
			} else {
				c.laddr = *laddr
			}
			c.raddr = *raddr
			return c, err
		}
		err = handleDialError(tpdu, cv.srcRef[:], tcp)
	}
	tcp.Close()
	if err == nil {
		err = errors.New("received an invalid TPKT")
	}
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
		MaxTpduSize:  int(getMaxTpduSize(repCv)),
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
	read, err := c.ReadTOSI(b)
	return read.N, err
}

// ReadTOSI is the same as Read, but it also indicates if the data comes
// from an expedited TPDU, and if it is the end of a TSDU.
func (c *TOSIConn) ReadTOSI(b []byte) (read ReadInfo, err error) {
	if b == nil {
		return read, errors.New("invalid input")
	}
	// see if there's something in the read buffer
	if c.readBuf != nil {
		read.EndOfTSDU = c.endOfTSDU
		read.Expedited = c.expedited
		copy(b, c.readBuf)
		if len(b) < len(c.readBuf) {
			// Cannot return the whole SDU
			read.N = len(b)
			c.readBuf = c.readBuf[len(b):]
			read.EndOfTSDU = false
		} else {
			read.N = len(c.readBuf)
			c.readBuf = nil
		}
		return read, nil
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
			return read, err
		}
		isDT, errIdx := isDT(tpdu)
		isED, _ := isED(tpdu)
		if isDT {
			read.N, err, read.EndOfTSDU = c.handleDt(b, tpdu)
			return read, err
		}
		if isED && c.UseExpedited {
			read.N, err, read.EndOfTSDU = c.handleEd(b, tpdu)
			read.Expedited = true
			return read, err
		}
		err = c.handleDataError(tpdu, errIdx)
	}
	if err == nil {
		err = errors.New("received an invalid TPKT")
	}
	return read, err
}

// parse an ED, handling errors and buffering issues
func (c *TOSIConn) handleEd(b, tpdu []byte) (n int, err error, end bool) {
	valid, erBuf := validateEd(tpdu)
	if !valid {
		// we got an invalid ED
		// reply with an ER
		go writeEr(c, erBuf)
		return 0, errors.New("received an invalid ED"), false
	}
	c.expedited = true
	return c.handleData(b, tpdu)
}

// parse a DT, handling errors and buffering issues
func (c *TOSIConn) handleDt(b, tpdu []byte) (n int, err error, end bool) {
	valid, erBuf := validateDt(tpdu, c.MaxTpduSize)
	if !valid {
		// we got an invalid DT
		// reply with an ER
		go writeEr(c, erBuf)
		return 0, errors.New("received an invalid DT"), false
	}
	c.expedited = false
	return c.handleData(b, tpdu)
}

// parse a DT or ED, handling buffering issues
func (c *TOSIConn) handleData(b, tpdu []byte) (n int, err error, end bool) {
	sduLen := len(tpdu) - dtMinLen
	end = (tpdu[2] == nrEot)
	copy(b, tpdu[dtMinLen:])
	if len(b) < sduLen {
		// Cannot return the whole SDU, save to buffer
		uncopiedLen := sduLen - len(b)
		uncopiedIdx := dtMinLen + len(b)
		c.readBuf = make([]byte, uncopiedLen)
		copy(c.readBuf, tpdu[uncopiedIdx:])
		n = len(b)
		c.endOfTSDU = end
		end = false
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
		go writeEr(c, tpdu[:errIdx])
		err = errors.New("received an invalid TPDU")
	}
	return
}

func writeEr(c *TOSIConn, tpdu []byte) {
	reply := tpkt(er(c.dstRef[:], erParamVal, tpdu))
	writePacket(&c.tcpConn, reply)
}

// RemoteAddr returns the remote network address.
func (c *TOSIConn) RemoteAddr() net.Addr {
	return &c.raddr
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *TOSIConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *TOSIConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *TOSIConn) SetWriteDeadline(t time.Time) error {
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
		return c.writeTpdu(b, c.MaxTpduSize-dtMinLen)
	}
	return c.writeTpdu(b, edMaxLen-edMinLen)
}

// write data using DT or ED TPDUs, depending on the maxSduSize argument.
func (c *TOSIConn) writeTpdu(b []byte, maxSduSize int) (n int, e error) {
	if b == nil {
		return 0, errors.New("invalid input")
	}
	var tpdu func([]byte, byte) []byte
	if maxSduSize == (c.MaxTpduSize - dtMinLen) {
		tpdu = dt
	} else if maxSduSize == (edMaxLen - edMinLen) {
		tpdu = ed
	}
	bufLen := len(b)
	// if b is too big, split it into smaller chunks
	if bufLen > maxSduSize {
		numWrites := (bufLen / maxSduSize)
		if (bufLen % maxSduSize) > 0 {
			numWrites += 1
		}
		var endOfTsdu byte
		for i := 0; i < numWrites; i++ {
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

// Network returns the address's network name, "tosi".
func (a *TOSIAddr) Network() string {
	return "tosi"
}

func (a *TOSIAddr) String() string {
	if a.TSel != nil {
		return a.IP.String() + ":" + string(a.TSel)
	}
	return a.IP.String()
}

// ResolveTOSIAddr parses addr as a TOSI address of the form tcp:tsel and
// resolves domain names to numeric addresses on the network tnet,
// which must be "tosi", "tosi4" or "tosi6". The tcp part must be a valid
// TCP address of the form host:port, as in "127.0.0.1:80", or just an IP address
// followed by ':', as in "127.0.0.1:". A literal IPv6 host address must be
// enclosed in square brackets, as in "[::]:80". tsel is the "trasport selector",
// which can be an arbitrary sequence of bytes. Thus "10.20.30.40:80:hello" is a
// valid address. If no TCP port is specified, as in "10.20.30.40::hello", it
// defaults to 102. The tsel parameter is optional, thus "10.20.30.40:80:"
// is a valid address.
func ResolveTOSIAddr(tnet, addr string) (tosiAddr *TOSIAddr, err error) {
	// after the last ':' we have the TSEL
	index := strings.LastIndex(addr, ":")
	if index < 0 {
		return nil, errors.New("invalid address")
	}
	tcp := addr[:index]
	var tsel string
	if len(addr) > (index + 1) {
		tsel = addr[index+1:]
	}
	// if no TCP port was specified, use default (102)
	_, port, err := net.SplitHostPort(tcp)
	if port == "" {
		tcp += rfc1006port
	}
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
		return nil, errors.New("invalid network")
	}
	tcpAddr, err := net.ResolveTCPAddr(tcpNet, tcp)
	if err != nil {
		return
	}
	tosiAddr = &TOSIAddr{TCPAddr: *tcpAddr}
	if tsel != "" {
		tosiAddr.TSel = []byte(tsel)
	}
	return tosiAddr, nil
}

// Accept implements the Accept method in the net.Listener interface;
// it waits for the next call and returns a generic net.Conn.
func (l *TOSIListener) Accept() (net.Conn, error) {
	return l.AcceptTOSI(nil)
}

// AcceptTOSI is the same as Accept, but it also takes a user function which
// should produce initial data to be sent during connection establishment,
// taking as input the data received from the caller (if present). In fact,
// RFC 1006 allows for the exchange of user data during connection establishment.
func (l *TOSIListener) AcceptTOSI(data func([]byte) []byte) (net.Conn, error) {
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
			var userData []byte
			cv := getConnVars(buf)
			if data != nil {
				userData = data(cv.userData)
			}
			return crReply(l, buf, userData, tcp)
		}
		if err == nil {
			// reply with an ER
			zeroDstRef := []byte{0x00, 0x00}
			reply = tpkt(er(zeroDstRef, erParamVal, buf[:tlen]))
			_, err = writePacket(tcp, reply)
		}
	}
	tcp.Close()
	if err == nil {
		err = errors.New("received an invalid TPKT")
	}
	return nil, err
}

// parse a CR, handling errors and sending a CC in response.
func crReply(l net.Listener, tpdu, data []byte, tcp net.Conn) (net.Conn, error) {
	var reply []byte
	var repCv connVars
	valid, erBuf := validateCr(tpdu, l.(*TOSIListener).addr.TSel)
	cv := getConnVars(tpdu)
	if valid {
		// reply with a CC
		repCv.locTsel = cv.locTsel
		repCv.remTsel = l.(*TOSIListener).addr.TSel
		if cv.prefTpduSize == nil {
			repCv.tpduSize = cv.tpduSize
		}
		repCv.prefTpduSize = cv.prefTpduSize
		repCv.srcRef = [2]byte{0x02, 0x02} // random non-zero value
		repCv.dstRef = cv.srcRef
		repCv.options = cv.options
		repCv.userData = data
		if len(repCv.userData) > maxDataLen {
			repCv.userData = repCv.userData[:maxDataLen]
		}
		reply = tpkt(cc(repCv))
	} else {
		// reply with an ER
		reply = tpkt(er(cv.srcRef[:], erParamVal, erBuf))
	}
	_, err := writePacket(tcp.(*net.TCPConn), reply)
	if valid && (err == nil) {
		// connection established
		// NOTE: in reply to our CC, we may also receive
		// an ER or DR. We don't check this now, but leave
		// it to the Read function.
		var tcpAddr *net.TCPAddr
		tcpAddr = tcp.RemoteAddr().(*net.TCPAddr)
		raddr := TOSIAddr{
			TCPAddr: *tcpAddr,
			TSel:    cv.locTsel}
		return &TOSIConn{
			tcpConn:      *tcp.(*net.TCPConn),
			laddr:        *l.(*TOSIListener).addr,
			raddr:        raddr,
			MaxTpduSize:  int(getMaxTpduSize(cv)),
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

// ListenTOSI announces on the TOSI address loc and returns a TOSI listener.
// tnet must be "tosi", "tosi4", or "tosi6".
func ListenTOSI(tnet string, loc *TOSIAddr) (*TOSIListener, error) {
	if loc == nil {
		return nil, errors.New("invalid local address")
	}
	tcpAddr := loc.TCPAddr
	tcpNet := tosiToTCPnet(tnet)
	if tcpNet == "" {
		// this check is needed by Go versions < 1.1
		return nil, errors.New("unknown network")
	}
	listener, err := net.ListenTCP(tcpNet, &tcpAddr)
	if err != nil {
		return nil, err
	}
	return &TOSIListener{addr: loc, tcpListener: *listener}, nil
}
