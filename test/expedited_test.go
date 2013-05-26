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
	"bytes"
	"testing"
	"time"
	"tosi"
)

// Test 1
// test expedited data write with 2 bytes. No error should occur.
// the server has a read buffer larger than 2 bytes.
func TestWrite2bytesED(t *testing.T) {
	// start a server
	go tosiServerRead2bytesED(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	// try to connect
	opt := tosi.DialOpt{Expedited: true}
	conn, err := tosi.DialOptTOSI("tosi", nil, tosiAddr, opt)
	checkErrorED(err, t)
	if conn.UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	_, err = conn.WriteTOSI([]byte{0x01, 0x02}, true)
	checkErrorED(err, t)
	time.Sleep(time.Second)
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
}

// Test 2
// test data write with maximum expedited SDU size (16). No error should occur.
// the server has a read buffer of exactly 16 bytes.
func TestWriteMaxED(t *testing.T) {
	// start a server
	go tosiServerReadMaxED(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	// try to connect
	opt := tosi.DialOpt{Expedited: true}
	conn, err := tosi.DialOptTOSI("tosi", nil, tosiAddr, opt)
	checkErrorED(err, t)
	if conn.UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	var buf [16]byte
	_, err = conn.WriteTOSI(buf[:], true)
	checkErrorED(err, t)
	time.Sleep(time.Second)
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
}

// Test 3
// test expedited data write with 2 bytes. No error should occur.
// the server has a read buffer of 1 byte, and performs two reads.
func TestWrite2bytesED2(t *testing.T) {
	// start a server
	go tosiServerRead1byteED(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	// try to connect
	opt := tosi.DialOpt{Expedited: true}
	conn, err := tosi.DialOptTOSI("tosi", nil, tosiAddr, opt)
	checkErrorED(err, t)
	if conn.UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	_, err = conn.WriteTOSI([]byte{0x01, 0x02}, true)
	checkErrorED(err, t)
	time.Sleep(time.Second)
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
}

// Test 4
// test expedited data write with more than maximum expedited SDU size (16).
// No error should occur. The server has a read buffer of exactly 16 bytes.
func TestWriteMaxED2(t *testing.T) {
	// start a server
	go tosiServerReadMaxED2(t)
	// wait for server to come up
	time.Sleep(time.Second)
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	// try to connect
	opt := tosi.DialOpt{Expedited: true}
	conn, err := tosi.DialOptTOSI("tosi", nil, tosiAddr, opt)
	checkErrorED(err, t)
	if conn.UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	var buf [27]byte
	_, err = conn.WriteTOSI(buf[:], true)
	checkErrorED(err, t)
	time.Sleep(time.Second)
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
}

// a tosi server reading 2 bytes. No fault is expected.
func tosiServerRead2bytesED(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
	checkErrorED(err, t)
	// listen for connections
	conn, err := listener.AcceptTOSI(nil)
	checkErrorED(err, t)
	if conn.(*tosi.TOSIConn).UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	buf := make([]byte, 100)
	read, err := conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 2 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf[:2], []byte{0x01, 0x02}) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == false {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
	err = listener.Close()
	checkErrorED(err, t)
}

// a tosi server reading 16 bytes. No fault is expected.
func tosiServerReadMaxED(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
	checkErrorED(err, t)
	// listen for connections
	conn, err := listener.AcceptTOSI(nil)
	checkErrorED(err, t)
	if conn.(*tosi.TOSIConn).UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	buf := make([]byte, 16)
	read, err := conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 16 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf, make([]byte, 16)) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == false {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
	err = listener.Close()
	checkErrorED(err, t)
}

// a tosi server reading 1 byte for two times. No fault is expected.
func tosiServerRead1byteED(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
	checkErrorED(err, t)
	// listen for connections
	conn, err := listener.AcceptTOSI(nil)
	checkErrorED(err, t)
	if conn.(*tosi.TOSIConn).UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	buf := make([]byte, 1)
	read, err := conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 1 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf[:], []byte{0x01}) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == true {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	read, err = conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 1 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf[:], []byte{0x02}) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == false {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
	err = listener.Close()
	checkErrorED(err, t)
}

// a tosi server reading 27 bytes. No fault is expected.
func tosiServerReadMaxED2(t *testing.T) {
	tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "127.0.0.1::100")
	checkErrorED(err, t)
	listener, err := tosi.ListenTOSI("tosi", tosiAddr)
	checkErrorED(err, t)
	// listen for connections
	conn, err := listener.AcceptTOSI(nil)
	checkErrorED(err, t)
	if conn.(*tosi.TOSIConn).UseExpedited == false {
		t.Log("Expedited service not available")
		t.FailNow()
	}
	buf := make([]byte, 16)
	read, err := conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 16 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf, make([]byte, 16)) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == true {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	buf = make([]byte, 11)
	read, err = conn.(*tosi.TOSIConn).ReadTOSI(buf)
	checkErrorED(err, t)
	if read.N != 11 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	if !bytes.Equal(buf, make([]byte, 11)) {
		t.Log("Wrong data values")
		t.FailNow()
	}
	if read.Expedited == false {
		t.Log("No expedited data received")
		t.FailNow()
	}
	if read.EndOfTSDU == false {
		t.Log("Wrong EndOfTSDU indication")
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkErrorED(err, t)
	err = listener.Close()
	checkErrorED(err, t)
}

// check for unexpected errors
func checkErrorED(err error, t *testing.T) {
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// check for expected errors
func checkWantedErrorED(err error, t *testing.T) {
	if err == nil {
		t.FailNow()
	}
}
