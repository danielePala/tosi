/*
 A sample tosi server.
 
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

package main

import (
	"fmt"
	"flag"
	"net"
	"os"
	"tosi"
)

func main() {
	// get address from cmd line
	var addr = flag.String("addr", "127.0.0.1:100", "ISO 8073 address, IP:TSEL")
	flag.Parse()
	// try to resolve the address
	tosiAddr, err := tosi.ResolveTosiAddr("tosi", *addr)
	checkError(err)
	listener, err := tosi.ListenTosi("tosi", tosiAddr)
	checkError(err)
	fmt.Printf("tosi: start listening at address %v\n", tosiAddr.String())
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
			listener.Close()
			os.Exit(1)
		}
		go TosiServer(conn)
	}
	listener.Close()
}

func TosiServer(conn net.Conn) {
	fmt.Println("Server started...")
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	checkError(err)
	fmt.Printf("Received something: %v\n", buf[0:n])
	conn.Close()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
