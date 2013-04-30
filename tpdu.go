/*
 Definition of the TPDUs used by ISO 8073 transport Class 0. 

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
	"encoding/binary"
	"fmt"
)

const (
	// len of a TPKT header
	tpktHlen = 4
	// default and min TPDU size
	defTpduSize = 65531
	minTpduSize = 128
	// CR-related defs
	crMinLen = 7
	crId     = 0xe0
	// CC-related defs
	ccMinLen = 7
	ccId     = 0xd0
	// CR and CC common defs
	connMinLen      = 7
	tpduSizeID      = 0xc0
	locTselID       = 0xc1
	remTselID       = 0xc2
	prefTpduSizeID  = 0xf0
	optionsID       = 0xc6
	tpduSizeLen     = 0x01
	prefTpduSizeLen = 0x04
	optionsLen      = 0x01
	tpduSizeMinVal  = 7
	tpduSizeMaxVal  = 11
	optionsMinVal   = 0
	optionsMaxVal   = 1
	classOptIdx     = 6
	// DR-related defs
	drMinLen    = 7
	drId        = 0x80
	drUnspec    = 0x00
	drCong      = 0x01
	drSna       = 0x02
	drUnknown   = 0x03
	infoID      = 0xe0
	drReasonIdx = 6
	drInfoIdx   = 9
	// ER-related defs
	erMinLen    = 5
	erId        = 0x70
	invalidID   = 0xc1
	erUnspec    = 0x00
	erParamCode = 0x01
	erTpdu      = 0x02
	erParamVal  = 0x03
	erCauseIdx  = 4
	erInvIdx    = 7
	// DT-related defs 
	dtMinLen = 3
	dtId     = 0xf0
	eotIdx   = 2
	nrEot    = 0x80
	nrNonEot = 0x00
	// ED-related defs
	edMinLen = 3
	edMaxLen = 19
	edId     = 0x10
)

// variables associated with a connection negotiation
type connVars struct {
	locTsel, remTsel []byte // local and remote transport selectors
	tpduSize         byte
	prefTpduSize     []byte // preferred TPDU size option
	srcRef, dstRef   [2]byte
	options          byte // "Additional option selection"
}

/* CR - Connection Request */
// the variable part of the CR TPDU can contain the Transport-Selectors, 
// maximum TPDU size, and preferred maximum TPDU size.
func cr(cv connVars) (tpdu []byte) {
	DST_REF := cv.dstRef[:]      // must always be zero
	SRC_REF := cv.srcRef[:]      // should identify the transport connection
	CLASS_OPTION := []byte{0x00} // class 0
	// construct the fixed part of CR
	fixed := append([]byte{crId}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, CLASS_OPTION...)
	// construct the variable part of CR       
	variable := setVarPart(cv)
	// assemble the whole tpdu
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is a CR, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte  
func isCR(incoming []byte) (found bool, tlen uint8) {
	found, tlen = isType(incoming, crId, crMinLen)
	if found {
		// the class option must be zero
		if incoming[classOptIdx] == 0x00 {
			return found, tlen
		}
		return false, classOptIdx + 1
	}
	return false, tlen
}

/* CC - Connection Confirm */
// the variable part of the CC TPDU can contain the Transport-Selectors, 
// maximum TPDU size, and preferred maximum TPDU size.
func cc(cv connVars) (tpdu []byte) {
	DST_REF := cv.dstRef[:]
	SRC_REF := cv.srcRef[:]
	CLASS_OPTION := []byte{0x00}
	fixed := append([]byte{ccId}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, CLASS_OPTION...)
	variable := setVarPart(cv)
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is a CC, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isCC(incoming []byte) (found bool, tlen uint8) {
	found, tlen = isType(incoming, ccId, ccMinLen)
	if found {
		// the class option must be zero
		if incoming[classOptIdx] == 0x00 {
			return found, tlen
		}
		return false, classOptIdx + 1
	}
	return false, tlen
}

// construct the variable part of a CR or CC packet
func setVarPart(cv connVars) (variable []byte) {
	// construct the local tsel option
	if cv.locTsel != nil {
		lTSEL := []byte{locTselID, byte(len(cv.locTsel))}
		lTSEL = append(lTSEL, cv.locTsel...)
		variable = append(variable, lTSEL...)
	}
	// construct the remote tsel option
	if cv.remTsel != nil {
		rTSEL := []byte{remTselID, byte(len(cv.remTsel))}
		rTSEL = append(rTSEL, cv.remTsel...)
		variable = append(variable, rTSEL...)
	}
	// construct the tpdu size option
	if cv.tpduSize > 0 {
		TSIZE := []byte{tpduSizeID, tpduSizeLen}
		TSIZE = append(TSIZE, cv.tpduSize)
		variable = append(variable, TSIZE...)
	}
	// construct the preferred tpdu size option
	if cv.prefTpduSize != nil {
		PTSIZE := []byte{prefTpduSizeID, byte(len(cv.prefTpduSize))}
		PTSIZE = append(PTSIZE, cv.prefTpduSize...)
		variable = append(variable, PTSIZE...)
	}
	// construct the "Additional option selection" option
	if cv.options > 0 {
		OPT := []byte{optionsID, optionsLen}
		OPT = append(OPT, cv.options)
		variable = append(variable, OPT...)
	}
	return
}

// decode the connection variables of a CR or CC packet, 
// extracting the components
func getConnVars(incoming []byte) (cv connVars) {
	copy(cv.dstRef[:], incoming[2:4])
	copy(cv.srcRef[:], incoming[4:6])
	// see if there is a variable part
	if len(incoming) <= connMinLen {
		return
	}
	// discard the fixed part
	incoming = incoming[connMinLen:]
	// decode the variable part
	for len(incoming) > 2 {
		id := incoming[0]
		pLen := int(incoming[1])
		incoming = incoming[2:]
		if len(incoming) < pLen {
			return
		}
		buf := bytes.NewBuffer(incoming[:pLen])
		switch id {
		case locTselID:
			cv.locTsel = make([]byte, pLen)
			binary.Read(buf, binary.BigEndian, &cv.locTsel)
		case remTselID:
			cv.remTsel = make([]byte, pLen)
			binary.Read(buf, binary.BigEndian, &cv.remTsel)
		case tpduSizeID:
			if pLen == tpduSizeLen {
				binary.Read(buf, binary.BigEndian, &cv.tpduSize)
			}
		case prefTpduSizeID:
			if pLen <= prefTpduSizeLen {
				cv.prefTpduSize = make([]byte, pLen)
				binary.Read(buf, binary.BigEndian, &cv.prefTpduSize)
			}
		case optionsID:
			if pLen == optionsLen {
				binary.Read(buf, binary.BigEndian, &cv.options)
			}
		}
		if len(incoming) > pLen {
			incoming = incoming[pLen:]
		} else {
			return
		}
	}
	return
}

// validate a CR TPDU, or return the bit pattern of the rejected TPDU header 
// up to and including the octet which caused the rejection.
func validateCr(incoming []byte, remTsel []byte) (valid bool, erBuf []byte) {
	// dstref must be zero
	if !bytes.Equal(incoming[2:4], []byte{0x00, 0x00}) {
		return false, incoming[:4]
	}
	// see if there is a variable part
	if len(incoming) <= connMinLen {
		// remTsel required?
		if remTsel != nil {
			return false, incoming
		}
		return true, nil // all ok
	}
	erBuf = incoming[:]
	index := connMinLen
	// discard the fixed part
	incoming = incoming[connMinLen:]
	remTselFound := false
	// decode the variable part
	for len(incoming) > 2 {
		id := incoming[0]
		pLen := int(incoming[1])
		incoming = incoming[2:]
		index = index + 2 + pLen
		if (len(incoming) < pLen) || (pLen < 1) {
			return false, erBuf // inconsistent option length
		}
		switch id {
		case locTselID: // always ok
		case remTselID:
			if !bytes.Equal(incoming[:pLen], remTsel) {
				return false, erBuf[:index] // wrong remTsel
			}
			remTselFound = true
		case tpduSizeID:
			if pLen > tpduSizeLen {
				return false, erBuf[:index] // invalid length
			}
			tpduSize := int8(incoming[0])
			if (tpduSize < tpduSizeMinVal) || (tpduSize > tpduSizeMaxVal) {
				return false, erBuf[:index] // invalid size
			}
		case prefTpduSizeID:
			if pLen > prefTpduSizeLen {
				return false, erBuf[:index] // invalid length
			}
			cv := connVars{prefTpduSize: incoming[:pLen]}
			size, _ := getMaxTpduSize(cv)
			if size > defTpduSize {
				return false, erBuf[:index] // invalid size
			}
		case optionsID:
			if pLen > optionsLen {
				return false, erBuf[:index] // invalid length
			}
			options := int8(incoming[0])
			if (options < optionsMinVal) || (options > optionsMaxVal) {
				return false, erBuf[:index] // invalid options
			}
		default:
			return false, erBuf[:index] // unknown option
		}
		if len(incoming) > pLen {
			incoming = incoming[pLen:]
		} else {
			// remTsel required?	
			if (remTsel != nil) && (remTselFound == false) {
				return false, erBuf[:]
			}
			return true, nil // all ok
		}
	}
	return
}

// validate a CC TPDU, or return the bit pattern of the rejected TPDU header 
// up to and including the octet which caused the rejection.
func validateCc(incoming []byte, crCv connVars) (valid bool, erBuf []byte) {
	// dstref must be equal to the srcref of the CR tpdu
	if !bytes.Equal(incoming[2:4], crCv.srcRef[:]) {
		return false, incoming[:4]
	}
	// see if there is a variable part
	if len(incoming) <= connMinLen {
		// all ok
		return true, nil
	}
	erBuf = incoming[:]
	index := connMinLen
	// discard the fixed part
	incoming = incoming[connMinLen:]
	// decode the variable part
	for len(incoming) > 2 {
		id := incoming[0]
		pLen := int(incoming[1])
		incoming = incoming[2:]
		index = index + 2 + pLen
		if (len(incoming) < pLen) || (pLen < 1) {
			return false, erBuf // inconsistent option length
		}
		switch id {
		case locTselID:
			if !bytes.Equal(incoming[:pLen], crCv.locTsel) {
				return false, erBuf[:index] // wrong locTsel
			}
		case remTselID:
			if !bytes.Equal(incoming[:pLen], crCv.remTsel) {
				return false, erBuf[:index] // wrong remTsel
			}
		case tpduSizeID:
			if pLen > tpduSizeLen {
				return false, erBuf[:index] // invalid length
			}
			tpduSize := int8(incoming[0])
			if (tpduSize < tpduSizeMinVal) || (tpduSize > tpduSizeMaxVal) {
				return false, erBuf[:index] // invalid size
			}
			ccCv := connVars{tpduSize: incoming[0]}
			ccSize, _ := getMaxTpduSize(ccCv)
			crSize, _ := getMaxTpduSize(crCv)
			if ccSize > crSize {
				return false, erBuf[:index] // invalid size
			}
		case prefTpduSizeID:
			if pLen > prefTpduSizeLen {
				return false, erBuf[:index] // invalid length
			}
			ccCv := connVars{prefTpduSize: incoming[:pLen]}
			ccSize, _ := getMaxTpduSize(ccCv)
			crSize, _ := getMaxTpduSize(crCv)
			if ccSize > crSize {
				return false, erBuf[:index] // invalid size
			}
		case optionsID:
			if pLen > optionsLen {
				return false, erBuf[:index] // invalid length
			}
			crOptions := int8(crCv.options)
			ccOptions := int8(incoming[0])
			if (ccOptions < optionsMinVal) || (ccOptions > optionsMaxVal) {
				return false, erBuf[:index] // invalid options
			}
			if ccOptions > crOptions {
				return false, erBuf[:index] // invalid options
			}
		default:
			return false, erBuf[:index] // unknown option
		}
		if len(incoming) > pLen {
			incoming = incoming[pLen:]
		} else {
			return true, nil // all ok
		}
	}
	return
}

// validate a DT TPDU, or return the bit pattern of the rejected TPDU header 
// up to and including the octet which caused the rejection.
func validateDt(incoming []byte, maxTpduSize uint64) (valid bool, erBuf []byte) {
	if uint64(len(incoming)) > maxTpduSize {
		return false, incoming[:maxTpduSize+1]
	}
	if (incoming[eotIdx] == 0x00) || (incoming[eotIdx] == 0x80) {
		return true, nil
	}
	return false, incoming[:dtMinLen]
}

// validate an ED TPDU, or return the bit pattern of the rejected TPDU header 
// up to and including the octet which caused the rejection.
func validateEd(incoming []byte) (valid bool, erBuf []byte) {
	return validateDt(incoming, edMaxLen)
}

/* DR - Disconnect Request */
// the variable part of the DR TPDU can contain a parameter allowing 
// additional information related to the clearing of the connection
func dr(conn TOSIConn, reason byte, info []byte) (tpdu []byte) {
	DST_REF := conn.dstRef[:]
	SRC_REF := conn.srcRef[:]
	fixed := append([]byte{drId}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, reason)
	var variable []byte
	// construct the info option
	if info != nil {
		maxSize := conn.maxTpduSize - drMinLen
		if maxSize < uint64(len(info)) {
			info = info[:maxSize]
		}
		variable = []byte{infoID, byte(len(info))}
		variable = append(variable, info...)
	}
	// assemble the whole tpdu
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is a DR, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isDR(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, drId, drMinLen)
}

// return info about the disconnection request
func getDRerror(tpdu []byte) (e error) {
	drReason := map[byte]string{
		0x00: "Reason not specified",
		0x01: "Congestion at TSAP",
		0x02: "Session entity not attached to TSAP",
		0x03: "Address unknown",
	}
	if len(tpdu) > drInfoIdx {
		return fmt.Errorf("DR - reason: %v, info: %v",
			drReason[tpdu[drReasonIdx]], tpdu[drInfoIdx:])
	}
	return fmt.Errorf("DR - reason: %v", drReason[tpdu[drReasonIdx]])
}

// returns the maximum TPDU size for a connection.
// According to RFC1006, the defaul value is 65531
// instead of 128.
func getMaxTpduSize(cv connVars) (size uint64, noPref bool) {
	noPref = false
	if cv.tpduSize > 0 {
		size_shift := uint8(cv.tpduSize) - 7
		size = (minTpduSize << size_shift)
	} else {
		size = defTpduSize
		noPref = true
	}
	if cv.prefTpduSize != nil {
		padding := make([]byte, 8-len(cv.prefTpduSize))
		paddedSize := append(padding, cv.prefTpduSize...)
		buf := bytes.NewBuffer(paddedSize)
		binary.Read(buf, binary.BigEndian, &size)
		size = size * minTpduSize
		noPref = false
	}
	return
}

/* ER - Error */
// the variable part of the ER TPDU contains the bit pattern of the rejected TPDU
// header up to and including the octet which caused the rejection. 
// This parameter is mandatory in class 0.
func er(dstRef []byte, cause byte, invalidTpdu []byte) (tpdu []byte) {
	DST_REF := dstRef
	fixed := append([]byte{erId}, DST_REF...)
	fixed = append(fixed, cause)
	var variable []byte
	// construct the invalidTpdu option
	variable = []byte{invalidID, byte(len(invalidTpdu))}
	variable = append(variable, invalidTpdu...)
	// assemble the whole tpdu
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is an ER, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isER(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, erId, erMinLen)
}

// return info about the error occurred
func getERerror(tpdu []byte) (e error) {
	erCause := map[byte]string{
		0x00: "Reason not specified",
		0x01: "Invalid parameter code",
		0x02: "Invalid TPDU type",
		0x03: "Invalid parameter value",
	}
	if len(tpdu) > erInvIdx {
		return fmt.Errorf("ER - cause: %v, invalid TPDU: %v",
			erCause[tpdu[erCauseIdx]], tpdu[erInvIdx:])
	}
	return fmt.Errorf("ER - cause: %v", erCause[tpdu[erCauseIdx]])
}

/* DT - Data Transfer */
func dt(userData []byte, endOfTsdu byte) (tpdu []byte) {
	tpdu = append([]byte{dtId}, endOfTsdu)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	tpdu = append(tpdu, userData...)
	return
}

// determine if a packet is a DT, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isDT(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, dtId, dtMinLen)
}

/* ED - Expedited Data. This is a non-standard TPDU defined in RFC 1006 */
/* It is equal to DT, just with a different ID */
func ed(userData []byte, endOfTsdu byte) (tpdu []byte) {
	tpdu = append([]byte{edId}, endOfTsdu)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	tpdu = append(tpdu, userData...)
	return
}

// determine if a packet is an ED, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isED(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, edId, edMinLen)
}

// determine if a packet is of a certain type, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including the faulty byte
func isType(incoming []byte, id byte, minLen int) (found bool, tlen uint8) {
	if len(incoming) < minLen {
		return false, uint8(len(incoming))
	}
	if incoming[1] == id {
		found = true
		buf := bytes.NewBuffer(incoming[0:1])
		binary.Read(buf, binary.BigEndian, &tlen)
		return
	}
	return false, 2
}

/* create a TPKT from a TPDU */
func tpkt(tpdu []byte) (tpkt []byte) {
	header := []byte{0x03, 0x00}
	// length includes this header too
	pLen := uint16(len(tpdu) + 4)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pLen)
	header = append(header, buf.Bytes()...)
	tpkt = append(header, tpdu...)
	return
}

// determine if a packet is a TPKT, and read its packet length 
func isTPKT(incoming []byte) (found bool, tlen uint16) {
	if len(incoming) < tpktHlen {
		return false, 0
	}
	if incoming[0] == 0x03 {
		found = true
		buf := bytes.NewBuffer(incoming[2:4])
		err := binary.Read(buf, binary.BigEndian, &tlen)
		if err == nil {
			return
		}
	}
	return false, 0
}
