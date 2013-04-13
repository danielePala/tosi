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

/*
Package tosi provides an implementation of rfc1006.

The protocol is defined at http://tools.ietf.org/html/rfc1006.
The implementation puts ISO/IEC 8072/8073 transport class 0
on top of a TCP/IP connection (on port 102).
ISO/IEC 8072/8073 is defined at http://www.itu.int/ITU-T/recommendations/rec.aspx?id=3262
and http://www.itu.int/ITU-T/recommendations/rec.aspx?id=3264.

The external interface is based on the constructs defined in
the 'net' package, and in particular the basic interface provided 
by the Dial, Listen, and Accept functions and the associated Conn 
and Listener interfaces. Please refer to that package's documentation
for general informations on their usage and philosophy, it can be
found here: http://golang.org/pkg/net/.

The Dial function connects to a server: 

 conn, err := net.Dial("tosi", "192.168.1.1:100")
 if err != nil {
         // handle error
 }
 fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
 status, err := bufio.NewReader(conn).ReadString('\n')
 // ...

A tosi address is composed by an IP address and an optional
"trasport selector (TSEL)" which can be an arbitrary sequence
of bytes. Thus '10.20.30.40:hello' is a valid address.

The Listen function creates servers:

 ln, err := net.Listen("tosi", ":8080")
 if err != nil {
         // handle error
 }
 for {
         conn, err := ln.Accept()
         if err != nil {
                 // handle error
                 continue
         }
         go handleConnection(conn)
 }

*/
package tosi