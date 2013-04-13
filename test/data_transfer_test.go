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
	"tosi"
	"time"
	"bytes"
)

// Test 1
// test data write with 2 bytes. No error should occur.
// the server has a read buffer larger than 2 bytes.
func TestWrite2bytes(t *testing.T) {
	// start a server
	go tosiServerRead2bytes(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
	// try to connect
        conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
        checkErrorDT(err, t)
	_, err = conn.Write([]byte{0x01, 0x02})
        checkErrorDT(err, t)
	time.Sleep(time.Second)
	// close connection
        err = conn.Close()
	checkErrorDT(err, t)
}

// Test 2
// test data write with maximum SDU size (65528). No error should occur.
// the server has a read buffer of exactly 65528 bytes.
func TestWriteMax(t *testing.T) {
	// start a server
	go tosiServerReadMax(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
	// try to connect
        conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
        checkErrorDT(err, t)
	var buf [65528]byte
	_, err = conn.Write(buf[:])
        checkErrorDT(err, t)
	time.Sleep(time.Second)
	// close connection
        err = conn.Close()
	checkErrorDT(err, t)
}

// Test 3
// test data write with 2 bytes. No error should occur.
// the server has a read buffer of 1 byte, and performs two reads.
func TestWrite2bytes2(t *testing.T) {
	// start a server
	go tosiServerRead1byte(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
	// try to connect
        conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
        checkErrorDT(err, t)
	_, err = conn.Write([]byte{0x01, 0x02})
        checkErrorDT(err, t)
	time.Sleep(time.Second)
	// close connection
        err = conn.Close()
	checkErrorDT(err, t)
}

// Test 4
// test data write with more than maximum SDU size (65528). No error should occur.
// the server has a read buffer of exactly 65528 bytes.
func TestWriteMax2(t *testing.T) {
	// start a server
	go tosiServerReadMax2(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
	// try to connect
        conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
        checkErrorDT(err, t)
	var buf [65529]byte
	_, err = conn.Write(buf[:])
        checkErrorDT(err, t)
	time.Sleep(time.Second)
	// close connection
        err = conn.Close()
	checkErrorDT(err, t)
}

// a tosi server reading 2 bytes. No fault is expected.
func tosiServerRead2bytes(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
        listener, err := tosi.ListenTOSI("tosi", tosiAddr)
        checkErrorDT(err, t)
	// listen for connections
        conn, err := listener.Accept()
        checkErrorDT(err, t)
	buf := make([]byte, 100) 
        n, err := conn.Read(buf)
        checkErrorDT(err, t)
	if n != 2 {
		t.Log("Wrong data size")
                t.FailNow()
	} 
	if !bytes.Equal(buf[:2], []byte{0x01, 0x02}) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	// close connection
	err = conn.Close()
	checkErrorDT(err, t)
	err = listener.Close()
	checkErrorDT(err, t)
}

// a tosi server reading 65528 bytes. No fault is expected.
func tosiServerReadMax(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
        listener, err := tosi.ListenTOSI("tosi", tosiAddr)
        checkErrorDT(err, t)
	// listen for connections
        conn, err := listener.Accept()
        checkErrorDT(err, t)
	buf := make([]byte, 65528) 
        n, err := conn.Read(buf)
        checkErrorDT(err, t)
	if n != 65528 {
		t.Log("Wrong data size")
                t.FailNow()
	}
	if !bytes.Equal(buf, make([]byte, 65528)) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	// close connection
	err = conn.Close()
	checkErrorDT(err, t)
	err = listener.Close()
	checkErrorDT(err, t)
}

// a tosi server reading 1 byte for two times. No fault is expected.
func tosiServerRead1byte(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
        listener, err := tosi.ListenTOSI("tosi", tosiAddr)
        checkErrorDT(err, t)
	// listen for connections
        conn, err := listener.Accept()
        checkErrorDT(err, t)
	buf := make([]byte, 1) 
        n, err := conn.Read(buf)
        checkErrorDT(err, t)
	if n != 1 {
		t.Log("Wrong data size")
                t.FailNow()
	} 
	if !bytes.Equal(buf[:], []byte{0x01}) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	n, err = conn.Read(buf)
        checkErrorDT(err, t)
	if n != 1 {
		t.Log("Wrong data size")
                t.FailNow()
	} 
	if !bytes.Equal(buf[:], []byte{0x02}) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	// close connection
	err = conn.Close()
	checkErrorDT(err, t)
	err = listener.Close()
	checkErrorDT(err, t)
}

// a tosi server reading 65529 bytes. No fault is expected.
func tosiServerReadMax2(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1:100")
        checkErrorDT(err, t)
        listener, err := tosi.ListenTOSI("tosi", tosiAddr)
        checkErrorDT(err, t)
	// listen for connections
        conn, err := listener.Accept()
        checkErrorDT(err, t)
	buf := make([]byte, 65528) 
        n, err := conn.Read(buf)
        checkErrorDT(err, t)
	if n != 65528 {
		t.Log("Wrong data size")
                t.FailNow()
	}
	if !bytes.Equal(buf, make([]byte, 65528)) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	buf = make([]byte, 1) 
        n, err = conn.Read(buf)
        checkErrorDT(err, t)
	if n != 1 {
		t.Log("Wrong data size")
                t.FailNow()
	}
	if !bytes.Equal(buf, []byte{0x00}) {
		t.Log("Wrong data values")
                t.FailNow()
        }
	// close connection
	err = conn.Close()
	checkErrorDT(err, t)
	err = listener.Close()
	checkErrorDT(err, t)
}

// check for unexpected errors
func checkErrorDT(err error, t *testing.T) {
        if err != nil {
                t.Log(err.Error())
                t.FailNow()
        }
}

// check for expected errors
func checkWantedErrorDT(err error, t *testing.T) {
        if err == nil {
                t.FailNow()
        }
}
