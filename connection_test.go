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
	"net"
	"strconv"
	"testing"
	"time"
)

const (
	// each test uses different ports for servers,
	// in order to avoid possible conflicts.
	connTest1Port  = 102
	connTest2Port  = 8080
	connTest3Port  = 8081
	connTest4Port  = 8082
	connTest5Port  = 8083
	connTest8Port  = 8084
	connTest12Port = 8085
	connTest13Port = 8086
	connTest14Port = 8087
	connTest15Port = 8088
	connTest16Port = 8089
)

// Test 1
// test connection establishment and closing. No error should occur.
func TestConn(t *testing.T) {
	// start a server
	go tosiServer(t, connTest1Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest1Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 2
// test connection establishment and closing.
// Don't specify any tsel. No error should occur.
func TestConnNoTsel(t *testing.T) {
	// start a server
	go tosiServerNoTsel(t, connTest2Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest2Port) + ":"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	if tosiAddr.String() != remAddr {
		t.Log(tosiAddr.String())
		t.FailNow()
	}
	// try to connect
	conn, err := DialTOSI("tosi", nil, tosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 3
// test connection establishment.
// Don't specify any tsel, while the server expects one. It should fail.
func TestConnNoTselFail(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest3Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest3Port) + ":"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	// try to connect
	_, err = DialTOSI("tosi", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 4
// test connection establishment and closing.
// Use the local address option. No error should occur.
func TestConnLAddr(t *testing.T) {
	// start a server
	go tosiServer(t, connTest4Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest4Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	localTOSIAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1:10102:999")
	checkError(err, t)
	// try to connect
	conn, err := DialTOSI("tosi", localTOSIAddr, tosiAddr)
	checkError(err, t)
	if conn.LocalAddr().String() != localTOSIAddr.String() {
		t.Log(conn.LocalAddr().String())
		t.Fail()
	}
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 5
// test connection establishment with wrong tsel. It should fail.
func TestWrongAddr(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest5Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest5Port) + ":10"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	// try to connect
	_, err = DialTOSI("tosi", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 6
// test connection establishment with wrong net. It should fail.
func TestWrongNet(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkError(err, t)
	// try to connect
	_, err = DialTOSI("tosiiii", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 7
// try to resolve address with wrong net. It should fail.
func TestWrongNet2(t *testing.T) {
	_, err := ResolveTOSIAddr("tosiiii", "127.0.0.1::100")
	checkWantedError(err, t)
}

// Test 8
// launch server with wrong net. It should fail.
func TestServerWrongNet(t *testing.T) {
	// start a faulty server
	go tosiServerWrongNet(t, connTest8Port)
}

// Test 9
// test connection establishment with nil remote address. It should fail.
func TestNilRaddr(t *testing.T) {
	// try to connect
	_, err := DialTOSI("tosi", nil, nil)
	checkWantedError(err, t)
}

// Test 10
// launch server with nil local address. It should fail.
func TestServerNilLaddr(t *testing.T) {
	// start a faulty server
	go tosiServerNilLaddr(t)
}

// Test 11
// test connection establishment with no server listening. It should fail.
func TestNoServer(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::")
	checkError(err, t)
	// try to connect
	_, err = DialTOSI("tosi", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 12
// test connection establishment with wrong srcRef. It should fail.
func TestWrongSrcRef(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest12Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest12Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	// try to connect
	var cv connVars
	cv.srcRef = [2]byte{0x00, 0x00} // wrong zero value
	cv.remTsel = tosiAddr.TSel
	_, err = dial("tosi", nil, tosiAddr, cv)
	checkWantedError(err, t)
}

// Test 13
// test connection establishment with wrong CR. It should fail.
func TestWrongCR(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest13Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest13Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi4", remAddr)
	checkError(err, t)
	// try to connect
	tcp, err := net.DialTCP("tcp4", nil, &tosiAddr.TCPAddr)
	checkError(err, t)
	_, err = tcp.Write(tpkt([]byte{0x00})) // send a wrong CR
	checkError(err, t)
	tcp.Close()
	time.Sleep(time.Millisecond)
}

// Test 14
// test connection establishment with wrong CR. It should fail.
func TestWrongCR2(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest14Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest14Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi4", remAddr)
	checkError(err, t)
	// try to connect
	tcp, err := net.DialTCP("tcp4", nil, &tosiAddr.TCPAddr)
	checkError(err, t)
	_, err = tcp.Write([]byte{0x00}) // send a wrong CR
	checkError(err, t)
	tcp.Close()
	time.Sleep(time.Millisecond)
}

// Test 15
// test connection establishment.
// Use the local address option.
// Don't specify any tsel, while the server expects one. It should fail.
func TestConnNoTselFailLocalAddress(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest15Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest15Port) + ":"
	tosiAddr, err := ResolveTOSIAddr("tosi", remAddr)
	checkError(err, t)
	localTOSIAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1:10102:999")
	checkError(err, t)
	// try to connect
	_, err = DialTOSI("tosi", localTOSIAddr, tosiAddr)
	checkWantedError(err, t)
}

// Test 16
// test connection establishment with wrong CR. It should fail.
func TestWrongCR3(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t, connTest16Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest16Port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi4", remAddr)
	checkError(err, t)
	// try to connect
	tcp, err := net.DialTCP("tcp4", nil, &tosiAddr.TCPAddr)
	checkError(err, t)
	var cv connVars
	cv.srcRef = [2]byte{0x01, 0x01}
	cv.remTsel = tosiAddr.TSel
	connReq := cr(cv)
	connReq[6] = 0x20                 // wrong class option
	_, err = tcp.Write(tpkt(connReq)) // send a wrong CR
	checkError(err, t)
	tcp.Close()
	time.Sleep(time.Millisecond)
}

// a tosi server. No fault is expected.
func tosiServer(t *testing.T, port int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	checkError(err, t)
	if tosiAddr.String() != locAddr {
		t.Log(tosiAddr.String())
		t.FailNow()
	}
	listener, err := ListenTOSI(tosiAddr.Network(), tosiAddr)
	checkError(err, t)
	// listen for connections
	_, err = listener.Accept()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server with no tsel. No fault is expected.
func tosiServerNoTsel(t *testing.T, port int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	checkError(err, t)
	listener, err := ListenTOSI("tosi", tosiAddr)
	checkError(err, t)
	// listen for connections
	_, err = listener.Accept()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server. A wrong Connection Request is expected.
func tosiServerWrongParam(t *testing.T, port int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	checkError(err, t)
	listener, err := ListenTOSI("tosi", tosiAddr)
	checkError(err, t)
	// listen for connections
	_, err = listener.Accept()
	checkWantedError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server with wrong net. It should fail.
func tosiServerWrongNet(t *testing.T, port int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":100"
	tosiAddr, err := ResolveTOSIAddr("tosi", locAddr)
	checkError(err, t)
	_, err = ListenTOSI("t", tosiAddr)
	checkWantedError(err, t)
}

// a tosi server with nil local address. It should fail.
func tosiServerNilLaddr(t *testing.T) {
	_, err := ListenTOSI("tosi", nil)
	checkWantedError(err, t)
}

// check for unexpected errors
func checkError(err error, t *testing.T) {
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// check for expected errors
func checkWantedError(err error, t *testing.T) {
	if err == nil {
		t.FailNow()
	}
}
