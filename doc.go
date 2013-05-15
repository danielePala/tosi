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
Package tosi provides an implementation of RFC 1006.

The protocol is defined at http://tools.ietf.org/html/rfc1006.
The implementation puts ISO/IEC 8072/8073 transport class 0 
(with some minor modifications) on top of a TCP/IP connection, on port 102 
by default, even if another port can be chosen.
ISO/IEC 8072/8073 is defined at 
http://www.itu.int/ITU-T/recommendations/rec.aspx?id=3262
and 
http://www.itu.int/ITU-T/recommendations/rec.aspx?id=3264.

The external interface is based on the constructs defined in
the 'net' package, and in particular the basic interface provided
by the Dial, Listen, and Accept functions and the associated Conn
and Listener interfaces. Please refer to that package's documentation
for general informations on their usage and philosophy, it can be
found here: http://golang.org/pkg/net/.

The DialTOSI function connects to a server:

 tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "[192.168.1.1:80]:100")
 if err != nil {
         // handle error
 }                                                                                                    
 conn, err := tosi.DialTOSI("tosi", nil, tosiAddr)
 if err != nil {
         // handle error
 }
 fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
 status, err := bufio.NewReader(conn).ReadString('\n')
 // ...

A tosi address is composed by a TCP address and an optional
"transport selector (TSEL)" which can be an arbitrary sequence
of bytes. Thus '[10.20.30.40:80]:hello' is a valid address, the
part inside the square brackets is the TCP address, and 'hello' is
the TSEL. The TCP port can be omitted, and in this case the default
value (102) will be used, as in '[10.20.30.40:]:hello'. The TSEL 
can also be omitted, as in '[10.20.30.40:]:'. 

The ListenTOSI function creates servers:

 tosiAddr, err := tosi.ResolveTOSIAddr("tosi", "[192.168.1.1:80]:100")
 if err != nil {
         // handle error
 }
 ln, err := tosi.ListenTOSI("tosi", tosiAddr)
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
