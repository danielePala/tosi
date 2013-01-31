/* GetHeadInfo
 */
package main

import (
	"flag"
	"os"
	"fmt"
	"tosi"
)

func main() {
	 // get address from cmd line  
        var addr = flag.String("addr", ":100", "ISO 8073 address to call")
        flag.Parse()

	// try to resolve the address
        tosiAddr, err := tosi.ResolveTosiAddr("tosi", *addr)
        checkError(err)
	conn, err := tosi.DialTosi("tosi", nil, tosiAddr)
	checkError(err)
	_, err = conn.Write([]byte{0x01, 0x02})
	checkError(err)
	fmt.Println("Nothing to do, closing connection...")
	conn.Close()
	os.Exit(0)
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s\n", err.Error())
		os.Exit(1)
	}
}
