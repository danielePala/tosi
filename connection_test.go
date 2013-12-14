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
	"testing"
	"time"
)

// Test 1
// test connection establishment and closing. No error should occur.
func TestConn(t *testing.T) {
	// start a server
	go tosiServer(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
	go tosiServerNoTsel(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::")
	checkError(err, t)
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
	go tosiServerWrongParam(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::")
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
	go tosiServer(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkError(err, t)
	localTOSIAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1:10102:999")
	checkError(err, t)
	// try to connect
	conn, err := DialTOSI("tosi", localTOSIAddr, tosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 5
// test connection establishment with wrong tsel. It should fail.
func TestWrongAddr(t *testing.T) {
	// start a server
	go tosiServerWrongParam(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::10")
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
	go tosiServerWrongNet(t)
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
	go tosiServerWrongParam(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
	go tosiServerWrongParam(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi4", "127.0.0.1::100")
	checkError(err, t)
	// try to connect
	tcp, err := net.DialTCP("tcp4", nil, &tosiAddr.TCPAddr)
	checkError(err, t)
	_, err = writePacket(tcp, tpkt([]byte{0x00})) // send a wrong CR
	checkError(err, t)
	tcp.Close()
	time.Sleep(time.Millisecond)
}

// a tosi server. No fault is expected.
func tosiServer(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkError(err, t)
	listener, err := ListenTOSI("tosi", tosiAddr)
	checkError(err, t)
	// listen for connections
	conn, err := listener.Accept()
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server with no tsel. No fault is expected.
func tosiServerNoTsel(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::")
	checkError(err, t)
	listener, err := ListenTOSI("tosi", tosiAddr)
	checkError(err, t)
	// listen for connections
	conn, err := listener.Accept()
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server. A wrong Connection Request is expected.
func tosiServerWrongParam(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
func tosiServerWrongNet(t *testing.T) {
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
