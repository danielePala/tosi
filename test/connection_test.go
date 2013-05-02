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
	"testing"
	"time"
	"tosi"
)

// Test 1
// test connection establishment and closing. No error should occur.
func TestConn(t *testing.T) {
	// start a server
	go tosiServer(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	// try to connect
	conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
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
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1")
	checkError(err, t)
	// try to connect
	conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
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
	go tosiServerWrongAddr(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1")
	checkError(err, t)
	// try to connect
	_, err = tosi.DialTOSI("tosi", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 4
// test connection establishment and closing. 
// Use the local address option. No error should occur.
func TestConnLAddr(t *testing.T) {
	// start a server
	go tosiServer(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	localTOSIAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:999")
	checkError(err, t)
	// try to connect
	conn, err := tosi.DialTOSI("tosi", localTOSIAddr, tosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 5
// test connection establishment with wrong tsel. It should fail.
func TestWrongAddr(t *testing.T) {
	// start a server
	go tosiServerWrongAddr(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:10")
	checkError(err, t)
	// try to connect
	_, err = tosi.DialTOSI("tosi", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 6
// test connection establishment with wrong net. It should fail.
func TestWrongNet(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	// try to connect
	_, err = tosi.DialTOSI("tosiiii", nil, tosiAddr)
	checkWantedError(err, t)
}

// Test 7
// try to resolve address with wrong net. It should fail.
func TestWrongNet2(t *testing.T) {
	_, err := tosi.ResolveTOSIAddr("tosiiii", "127.0.0.1:100")
	checkWantedError(err, t)
}

// Test 8
// launch server with wrong net. It should fail.
func TestServerWrongNet(t *testing.T) {
	// start a faulty server
	go tosiServerWrongNet(t)
}

// a tosi server. No fault is expected.
func tosiServer(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
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
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1")
	checkError(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
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

// a tosi server. A wrong tsel (or no tsel) is expected.
func tosiServerWrongAddr(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
	checkError(err, t)
	// listen for connections
	_, err = listener.Accept()
	checkWantedError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a tosi server with wrong net. It should fail.
func tosiServerWrongNet(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
	checkError(err, t)
	_, err = tosi.ListenTOSI("t", tosiAddr)
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
