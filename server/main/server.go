/* DaytimeServer
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
	var addr = flag.String("addr", ":100", "ISO 8073 address")
	flag.Parse()

	// try to resolve the address
	tosiAddr, err := tosi.ResolveTosiAddr("tosi", *addr)
	checkError(err)
	listener, err := tosi.ListenTosi("tosi", tosiAddr)
	checkError(err)

	for {
		conn, err := listener.Accept()
		checkError(err)
		go THandler(conn)
	}
}

func THandler(conn net.Conn) {
	fmt.Println("Handler started...")
	buf := make([]byte, 100)
	_, err := conn.Read(buf)
	checkError(err)
	fmt.Printf("Received something: %v\n", buf)
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
