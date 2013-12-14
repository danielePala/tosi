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
 along with   If not, see <http://www.gnu.org/licenses/>.

*/

package tosi

import (
	"bytes"
	"testing"
	"time"
)

const (
	maxSduSize = 65528
)

// Test 1
// test data write with 2 bytes. No error should occur.
// the server has a read buffer of 2 bytes.
func TestWrite2bytes(t *testing.T) {
	testPayloads(t, DialOpt{}, []byte{0x01, 0x02})
}

// Test 2
// test data write with maximum SDU size (default: 65528). No error should occur.
// the server has a read buffer of exactly maxSduSize bytes.
func TestWriteMax(t *testing.T) {
	testPayloads(t, DialOpt{}, make([]byte, maxSduSize))
}

// Test 3
// test data write with 2 bytes. No error should occur.
// the server performs two reads.
func TestWrite2bytes2(t *testing.T) {
	testPayloads(t, DialOpt{}, []byte{0x01}, []byte{0x02})
}

// Test 4
// test data write with more than maximum SDU size (default: 65528).
// No error should occur.
func TestWriteMax2(t *testing.T) {
	testPayloads(t, DialOpt{}, make([]byte, maxSduSize), []byte{0x04})
}

// Test 5
// test data write with custom TPDU size (512 bytes). No error should occur.
func TestWriteCustom(t *testing.T) {
	customTpduSze := 512
	opt := DialOpt{MaxTPDUSize: customTpduSze}
	testPayloads(t, opt, make([]byte, customTpduSze-3), []byte{0x33})
}

// Test 6
// test data write with custom TPDU size (4096 bytes). No error should occur.
func TestWriteCustom2(t *testing.T) {
	customTpduSze := 4096
	opt := DialOpt{MaxTPDUSize: customTpduSze}
	testPayloads(t, opt, make([]byte, customTpduSze-3), []byte{0x33})
}

// Test 7
// test data write with DR. The server should close the connection.
func TestWriteDR(t *testing.T) {
	// start a server
	go tosiServerFault(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
	_, err = writePacket(&conn.tcpConn, payload) // send a DR
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// send a given set of payloads
func testPayloads(t *testing.T, opt DialOpt, payloads ...[]byte) {
	var allPayloads []byte
	for _, payload := range payloads {
		allPayloads = append(allPayloads, payload...)
	}
	// start a server
	go tosiServerReadPayloads(t, payloads...)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::105")
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
	_, err = conn.Write(allPayloads)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// a tosi server reading arbitrary payloads. No fault is expected.
func tosiServerReadPayloads(t *testing.T, payloads ...[]byte) {
	var conn *TOSIConn
	var listener *TOSIListener
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::105")
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
	defer cleanup(t, conn, listener)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	for n, payload := range payloads {
		size := len(payload)
		end := n == (len(payloads) - 1)
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
		if read.Expedited == true {
			t.Log("Expedited data received")
			t.FailNow()
		}
		if read.EndOfTSDU != end {
			t.Logf("Wrong EndOfTSDU indication")
			t.FailNow()
		}
	}
}

// a tosi server reading 100 bytes. A DR is expected from client.
func tosiServerFault(t *testing.T) {
	var conn *TOSIConn
	var listener *TOSIListener
	tosiAddr, err := ResolveTOSIAddr("tosi", "127.0.0.1::100")
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
		cleanup(t, conn, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	buf := make([]byte, 100)
	_, err = conn.ReadTOSI(buf)
	if err == nil {
		cleanup(t, conn, listener)
		t.FailNow()
	}
	switch err.(type) {
	case *RemoteError:
		ok := bytes.Equal(err.(*RemoteError).Info, []byte{0x02})
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
