/*
 Copyright 2013-2021 Daniele Pala <pala.daniele@gmail.com>

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
 along with tosi. If not, see <http://www.gnu.org/licenses/>.

*/

package tosi

import (
	"bytes"
	"strconv"
	"testing"
	"time"
)

const (
	maxSduSize = 65528
	// each test uses different ports for servers,
	// in order to avoid possible conflicts.
	dataTest1Port  = 8090
	dataTest2Port  = 8091
	dataTest3Port  = 8092
	dataTest4Port  = 8093
	dataTest5Port  = 8094
	dataTest6Port  = 8095
	dataTest7Port  = 8096
	dataTest8Port  = 8097
	dataTest9Port  = 8098
	dataTest10Port = 8099
	dataTest11Port = 8100
	dataTest12Port = 8101
	dataTest13Port = 8102
	dataTest14Port = 8103
	dataTest15Port = 8104
	dataTest16Port = 8105
	dataTest17Port = 8106
)

// Test 1
// test data write with 2 bytes.
// No error should occur.
func TestWrite2bytes(t *testing.T) {
	testPayloads(t, DialOpt{}, dataTest1Port, []byte{0x01, 0x02})
}

// Test 2
// test data write with maximum SDU size (default: 65528).
// No error should occur.
func TestWriteMax(t *testing.T) {
	testPayloads(t, DialOpt{}, dataTest2Port, make([]byte, maxSduSize))
}

// Test 3
// test data write with 2 bytes.
// No error should occur. The server performs two reads.
func TestWrite1byte2times(t *testing.T) {
	testPayloads(t, DialOpt{}, dataTest3Port, []byte{0x01}, []byte{0x02})
}

// Test 4
// test data write with more than maximum SDU size (default: 65528).
// No error should occur.
func TestWriteMoreThanMax(t *testing.T) {
	maxBuf := make([]byte, maxSduSize)
	testPayloads(t, DialOpt{}, dataTest4Port, maxBuf, []byte{0x04})
}

// Test 5
// test data write with custom TPDU size (512 bytes).
// No error should occur.
func TestWriteCustom1(t *testing.T) {
	customTpduSze := 512
	opt := DialOpt{MaxTPDUSize: customTpduSze}
	buf := make([]byte, customTpduSze-3)
	testPayloads(t, opt, dataTest5Port, buf, []byte{0x33})
}

// Test 6
// test data write with custom TPDU size (4096 bytes).
// No error should occur.
func TestWriteCustom2(t *testing.T) {
	customTpduSze := 4096
	opt := DialOpt{MaxTPDUSize: customTpduSze}
	buf := make([]byte, customTpduSze-3)
	testPayloads(t, opt, dataTest6Port, buf, []byte{0x33})
}

// Test 7
// test data write with DR.
// The server should close the connection.
func TestWriteDR(t *testing.T) {
	// start a server
	go tosiServerReadDR(t, dataTest7Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest7Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	defer cleanup(t, conn, nil)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	payload := tpkt(dr(*conn, 0x01, []byte{0x02}))
	_, err = conn.tcpConn.Write(payload) // send a DR
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// Test 8
// test expedited data write with 2 bytes.
// No error should occur.
func TestWrite2bytesExpedited(t *testing.T) {
	opt := DialOpt{Expedited: true}
	testPayloads(t, opt, dataTest8Port, []byte{0x01, 0x02})
}

// Test 9
// test data write with maximum expedited SDU size (16).
// No error should occur.
func TestWriteMaxExpedited(t *testing.T) {
	opt := DialOpt{Expedited: true}
	testPayloads(t, opt, dataTest9Port, make([]byte, 16))
}

// Test 10
// test expedited data write with 2 bytes.
// No error should occur. The server performs two reads.
func TestWrite1byte2timesExpedited(t *testing.T) {
	opt := DialOpt{Expedited: true}
	testPayloads(t, opt, dataTest10Port, []byte{0x01}, []byte{0x02})
}

// Test 11
// test expedited data write with more than maximum expedited SDU size (16).
// No error should occur.
func TestWriteMoreThanMaxExpedited(t *testing.T) {
	opt := DialOpt{Expedited: true}
	testPayloads(t, opt, dataTest11Port, make([]byte, 16), make([]byte, 11))
}

// Test 12
// test data write with 2 bytes.
// The server sends a DR.
func TestReadDR(t *testing.T) {
	// start a server
	go tosiServerWriteDR(t, dataTest12Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest12Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	if err == nil {
		cleanup(t, conn, nil)
		t.FailNow()
	}
	switch err.(type) {
	case *ProtocolError:
		ok := bytes.Equal(err.(*ProtocolError).Info, []byte{0x02})
		if (err.Error() != drReason[0x01]) || !ok {
			t.Log(err.Error())
			t.Fail()
		}
	default:
		t.Log(err.Error())
		t.Fail()
	}
}

// Test 13
// test data write with 2 bytes.
// The server sends a wrong CC.
func TestReadWrongCC(t *testing.T) {
	// start a server
	go tosiServerWriteWrongCC(t, dataTest13Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest13Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	if err == nil {
		cleanup(t, conn, nil)
		t.FailNow()
	}
	switch err.(type) {
	case *ProtocolError:
		if err.Error() != ErrBadCC {
			t.Log(err.Error())
			t.Fail()
		}
	default:
		t.Log(err.Error())
		t.Fail()
	}
}

// Test 14
// test data write with 2 bytes.
// The server sends a wrong TPKT.
func TestReadWrongTPKT(t *testing.T) {
	// start a server
	go tosiServerWriteWrongTPKT(t, dataTest14Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest14Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	if err == nil {
		cleanup(t, conn, nil)
		t.FailNow()
	}
	switch err.(type) {
	case *ProtocolError:
		if err.Error() != ErrBadTPKT {
			t.Log(err.Error())
			t.Fail()
		}
	default:
		t.Log(err.Error())
		t.Fail()
	}
}

// Test 15
// test data write with 2 bytes.
// The server sends a wrong reply (not a CC).
func TestReadWrongReply(t *testing.T) {
	// start a server
	go tosiServerWriteWrongReply(t, dataTest15Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest15Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	if err == nil {
		cleanup(t, conn, nil)
		t.FailNow()
	}
	switch err.(type) {
	case *ProtocolError:
		if err.Error() != ErrUnknownReply {
			t.Log(err.Error())
			t.Fail()
		}
	default:
		t.Log(err.Error())
		t.Fail()
	}
}

// Test 16
// test data write with 2 bytes.
// The server sends an invalid reply (a CC with a missing byte).
func TestReadInvalidCC(t *testing.T) {
	// start a server
	go tosiServerWriteInvalidCC(t, dataTest16Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(dataTest16Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	if err == nil {
		cleanup(t, conn, nil)
		t.FailNow()
	}
}

// Test 17
// test data write with more than maximum SDU size (default: 65528).
// The server reads 1 byte at a time. No error should occur.
func TestWriteMoreThanMaxMerged(t *testing.T) {
	buf := make([]byte, maxSduSize)
	testMerged(t, DialOpt{}, dataTest17Port, buf, []byte{0x04})
}

// send a given set of payloads as a single message
func testPayloads(t *testing.T, opt DialOpt, port int, payloads ...[]byte) {
	var allPayloads []byte
	for _, payload := range payloads {
		allPayloads = append(allPayloads, payload...)
	}
	// start a server
	go tosiSrvRead(t, opt, port, payloads...)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialOptTOSI("tosi", nil, tosiAddr, opt)
	defer cleanup(t, conn, nil)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	if conn.UseExpedited != opt.Expedited {
		t.Log("Wrong expedited indication")
		t.FailNow()
	}
	_, err = conn.WriteTOSI(allPayloads, opt.Expedited)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// send a given set of payloads as a single message, with server
// reading 1 byte at a time
func testMerged(t *testing.T, opt DialOpt, port int, payloads ...[]byte) {
	var allPayloads []byte
	for _, payload := range payloads {
		allPayloads = append(allPayloads, payload...)
	}
	// start a server
	go tosiSrvReadPayload(t, opt, allPayloads, port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialOptTOSI("tosi", nil, tosiAddr, opt)
	defer cleanup(t, conn, nil)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	if conn.UseExpedited != opt.Expedited {
		t.Log("Wrong expedited indication")
		t.FailNow()
	}
	_, err = conn.WriteTOSI(allPayloads, opt.Expedited)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// a tosi server reading arbitrary payloads. No fault is expected.
func tosiSrvRead(t *testing.T, opt DialOpt, port int, payloads ...[]byte) {
	var conn *TOSIConn
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		cleanup(t, nil, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	// listen for connections
	conn, err = listener.AcceptTOSI(nil)
	defer cleanup(t, nil, listener)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	if conn.UseExpedited != opt.Expedited {
		t.Log("Wrong expedited indication")
		t.FailNow()
	}
	totalSize := 0
	for n, payload := range payloads {
		size := len(payload)
		totalSize += size
		end := n == (len(payloads) - 1)
		if opt.Expedited && totalSize >= (edMaxLen-edMinLen) {
			end = true
		}
		buf := make([]byte, size)
		read, err := conn.ReadTOSI(buf)
		if err != nil {
			t.Log(err.Error())
			t.FailNow()
		}
		if read.N != size {
			t.Log("Wrong data size")
			t.FailNow()
		}
		if !bytes.Equal(buf[:], payload) {
			t.Log("Wrong data values")
			t.FailNow()
		}
		if read.Expedited != opt.Expedited {
			t.Log("Wrong expedited indication")
			t.FailNow()
		}
		if read.EndOfTSDU != end {
			t.Logf("Wrong EndOfTSDU indication")
			t.FailNow()
		}
		if opt.Expedited && totalSize >= (edMaxLen-edMinLen) {
			return
		}
	}
}

// a tosi server reading a payload, one byte at a time. No fault is expected.
func tosiSrvReadPayload(t *testing.T, opt DialOpt, payload []byte, port int) {
	var conn *TOSIConn
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		cleanup(t, nil, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	// listen for connections
	conn, err = listener.AcceptTOSI(nil)
	defer cleanup(t, nil, listener)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	if conn.UseExpedited != opt.Expedited {
		t.Log("Wrong expedited indication")
		t.FailNow()
	}
	for i := 0; i < len(payload); i++ {
		end := i == (len(payload) - 1)
		buf := make([]byte, 1)
		read, err := conn.ReadTOSI(buf)
		if err != nil {
			t.Log(err.Error())
			t.FailNow()
		}
		if read.N != 1 {
			t.Log("Wrong data size")
			t.FailNow()
		}
		if buf[0] != payload[i] {
			t.Log("Wrong data values")
			t.FailNow()
		}
		if read.Expedited != opt.Expedited {
			t.Log("Wrong expedited indication")
			t.FailNow()
		}
		if read.EndOfTSDU != end {
			t.Logf("Wrong EndOfTSDU indication")
			t.FailNow()
		}
	}
}

// a tosi server reading 100 bytes. A DR is expected from client.
func tosiServerReadDR(t *testing.T, port int) {
	var conn *TOSIConn
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// listen for connections
	conn, err = listener.AcceptTOSI(nil)
	if err != nil {
		cleanup(t, nil, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	n, err := conn.Read(nil)
	if n != 0 || err != nil {
		cleanup(t, nil, listener)
		t.FailNow()
	}
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	if err == nil {
		cleanup(t, nil, listener)
		t.FailNow()
	}
	switch err.(type) {
	case *ProtocolError:
		ok := bytes.Equal(err.(*ProtocolError).Info, []byte{0x02})
		if (err.Error() != drReason[0x01]) || !ok {
			t.Log(err.Error())
			t.Fail()
		}
	default:
		t.Log(err.Error())
		t.Fail()
	}
	cleanup(t, nil, listener)
}

// a tosi server writing a DR.
func tosiServerWriteDR(t *testing.T, port int) {
	var conn TOSIConn
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	defer cleanup(t, nil, listener)
	// listen for connections
	tcp, err := listener.tcpListener.AcceptTCP()
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	conn.srcRef = [2]byte{0x00, 0x00}
	conn.dstRef = [2]byte{0x01, 0x01}
	conn.MaxTpduSize = 128
	payload := tpkt(dr(conn, 0x01, []byte{0x02}))
	_, err = tcp.Write(payload) // send a DR
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// a tosi server writing a wrong CC.
func tosiServerWriteWrongCC(t *testing.T, port int) {
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	defer cleanup(t, nil, listener)
	// listen for connections
	tcp, err := listener.tcpListener.AcceptTCP()
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	payload := tpkt(cc(connVars{}))
	_, err = tcp.Write(payload) // send a wrong CC
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// a tosi server writing a wrong TPKT.
func tosiServerWriteWrongTPKT(t *testing.T, port int) {
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	defer cleanup(t, nil, listener)
	// listen for connections
	tcp, err := listener.tcpListener.AcceptTCP()
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	payload := cc(connVars{})
	_, err = tcp.Write(payload) // send a wrong TPKT
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// a tosi server writing a wrong reply (not a CC).
func tosiServerWriteWrongReply(t *testing.T, port int) {
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	defer cleanup(t, nil, listener)
	// listen for connections
	tcp, err := listener.tcpListener.AcceptTCP()
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	payload := tpkt(dt([]byte{0x01}, 0x01))
	_, err = tcp.Write(payload) // send a wrong reply
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// a tosi server writing an invalid CC (one byte missing).
func tosiServerWriteInvalidCC(t *testing.T, port int) {
	var listener *TOSIListener
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenTOSI("tosi", tosiAddr)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	defer cleanup(t, nil, listener)
	// listen for connections
	tcp, err := listener.tcpListener.AcceptTCP()
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	payload := tpkt(cc(connVars{}))
	replyLen := len(payload) - 1
	_, err = tcp.Write(append(payload[0:replyLen], 0x00)) // send an invalid CC
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// a cleanup utility function
func cleanup(t *testing.T, conn *TOSIConn, listener *TOSIListener) {
	var err error
	if conn != nil { // close connection
		err = conn.Close()
		if err != nil {
			t.Log(err.Error())
			t.Fail()
		}
	}
	if listener != nil { // close listener
		err = listener.Close()
		if err != nil {
			t.Log(err.Error())
			t.Fail()
		}
	}
}
