/*
 Definition of the TPDUs used by ISO 8073 transport Class 0 (with
 modifications defined in RFC 1006) and associated validation functions.

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
)

const (
	// TPKT-related defs
	tpktHlen     = 4    // length of a TPKT header
	tpktVrsn     = 0x03 // TPKT version field
	tpktReserved = 0x00 // TPKT reserved field
	// default and min TPDU size
	defTpduSize = 65531
	minTpduSize = 128
	// CR-related defs
	crID = 0xe0 // ID of a CR TPDU
	// CC-related defs
	ccID = 0xd0 // ID of a CR TPDU
	// CR and CC common defs
	connMinLen      = 7    // min length of a CR or CC TPDU
	tpduSizeID      = 0xc0 // ID of the TPDU size field
	locTselID       = 0xc1 // ID of the local TSEL field
	remTselID       = 0xc2 // ID of the remote TSEL field
	prefTpduSizeID  = 0xf0 // ID of the preferred TPDU size field
	optionsID       = 0xc6 // ID of the options field
	tpduSizeLen     = 0x01 // length of the TPDU size field
	prefTpduSizeLen = 0x04 // max length of the preferred TPDU size field
	optionsLen      = 0x01 // length of the options field
	tpduSizeMin     = 7    // min value of the TPDU size field
	tpduSizeMax     = 11   // max value of the TPDU size field
	optionsMin      = 0    // min value of the options field
	optionsMax      = 1    // max value of the options field
	expeditedOpt    = 1    // expedited data option
	classOptIdx     = 6    // index of the class option field
	maxDataLen      = 32   // max length of initial data
	// DR-related defs
	drMinLen    = 7    // min length of a DR TPDU
	drID        = 0x80 // ID of a DR TPDU
	drUnspec    = 0x00 // reason "Reason not specified"
	drCong      = 0x01 // reason "Congestion at TSAP"
	drSna       = 0x02 // reason "Session entity not attached to TSAP"
	drUnknown   = 0x03 // reason "Address unknown"
	infoID      = 0xe0 // ID of the info field
	drReasonIdx = 6    // index of the reason field
	drInfoIdx   = 9    // index of the info field
	// ER-related defs
	erMinLen    = 5    // min length of an ER TPDU
	erID        = 0x70 // ID of an ER TPDU
	invalidID   = 0xc1 // ID of the invalid field
	erUnspec    = 0x00 // error "Reason not specified"
	erParamCode = 0x01 // error "Invalid parameter code"
	erTpdu      = 0x02 // error "Invalid TPDU type"
	erParamVal  = 0x03 // error "Invalid parameter value"
	erCauseIdx  = 4    // index of the cause field
	erInvIdx    = 7    // start index of the invalid TPDU
	// DT-related defs
	dtMinLen = 3    // min length of a DT TPDU
	dtID     = 0xf0 // ID of a DT TPDU
	// ED-related defs
	edMinLen = 3    // min length of an ED TPDU
	edMaxLen = 19   // max length of an ED TPDU
	edID     = 0x10 // ID of an ED TPDU
	// DT and ED common defs
	eotIdx   = 2    // index of the EOT field
	nrEot    = 0x80 // EOT option selection
	nrNonEot = 0x00 // non-EOT option selection
)

var (
	drReason = map[byte]string{
		0x00: "Disconnect Request: Reason not specified",
		0x01: "Disconnect Request: Congestion at TSAP",
		0x02: "Disconnect Request: Session entity not attached to TSAP",
		0x03: "Disconnect Request: Address unknown",
	}

	erCause = map[byte]string{
		0x00: "TPDU Error: Reason not specified",
		0x01: "TPDU Error: Invalid parameter code",
		0x02: "TPDU Error: Invalid TPDU type",
		0x03: "TPDU Error: Invalid parameter value",
	}
)

// variables associated with a connection negotiation
type connVars struct {
	locTsel, remTsel []byte  // local and remote transport selectors
	tpduSize         byte    // TPDU size option
	prefTpduSize     []byte  // preferred TPDU size option
	srcRef, dstRef   [2]byte // src and dst references
	options          byte    // "Additional option selection"
	userData         []byte  // initial user data
}

/* CR - Connection Request */
// the variable part of the CR TPDU can contain the Transport-Selectors,
// maximum TPDU size, and preferred maximum TPDU size.
func cr(cv connVars) (tpdu []byte) {
	DST_REF := cv.dstRef[:]      // must always be zero
	SRC_REF := cv.srcRef[:]      // should identify the transport connection
	CLASS_OPTION := []byte{0x00} // class 0
	// construct the fixed part of CR
	fixed := append([]byte{crID}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, CLASS_OPTION...)
	// construct the variable part of CR
	variable := setVarPart(cv)
	// assemble the whole tpdu
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append(tpdu, cv.userData...) // add initial user data, if present
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is a CR, and read its Length Indicator
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isCR(incoming []byte) (found bool, tlen uint8) {
	found, tlen = isType(incoming, crID, connMinLen)
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
	fixed := append([]byte{ccID}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, CLASS_OPTION...)
	variable := setVarPart(cv)
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append(tpdu, cv.userData...) // add initial user data, if present
	tpdu = append([]byte{pLen}, tpdu...)
	return
}

// determine if a packet is a CC, and read its Length Indicator
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isCC(incoming []byte) (found bool, tlen uint8) {
	found, tlen = isType(incoming, ccID, connMinLen)
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
	// calculate the length of fixed+variable part
	fixVarLen := incoming[0] + 1 // add the Length Indicator size (1 byte)
	if len(incoming) > int(fixVarLen) {
		cv.userData = incoming[fixVarLen:] // we have some user data
		incoming = incoming[:fixVarLen]
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
		switch id {
		case locTselID:
			cv.locTsel = incoming[:pLen]
		case remTselID:
			cv.remTsel = incoming[:pLen]
		case tpduSizeID:
			if pLen == tpduSizeLen {
				cv.tpduSize = incoming[0]
			}
		case prefTpduSizeID:
			if pLen <= prefTpduSizeLen {
				cv.prefTpduSize = incoming[:pLen]
			}
		case optionsID:
			if pLen == optionsLen {
				cv.options = incoming[0]
			}
		}
		incoming = incoming[pLen:]
	}
	return
}

// validate a CR TPDU, or return the bit pattern of the rejected TPDU header
// up to and including the octet which caused the rejection.
func validateCR(incoming []byte, remTsel []byte) (bool, []byte) {
	// validate fixed part - dstref must be zero
	ok, vars := validateFixed(incoming, []byte{0x00, 0x00}, remTsel != nil)
	if !ok || vars == nil {
		return ok, vars
	}
	index := connMinLen
	remTselFound := false
	// decode the variable part
	for len(vars) > 2 {
		id := vars[0]
		optLen := int(vars[1]) + 2
		index += optLen
		if (len(vars) < optLen) || (optLen < 3) {
			return false, incoming // inconsistent option length
		}
		switch id {
		case locTselID: // always ok
		case remTselID:
			ok = bytes.Equal(vars[2:optLen], remTsel)
			remTselFound = true
		case tpduSizeID:
			ok = validCRTpduSize(vars)
		case prefTpduSizeID:
			ok = validCRPrefTpduSize(vars)
		case optionsID:
			ok = validCROptions(vars)
		default:
			ok = false // unknown option
		}
		if !ok {
			return false, incoming[:index]
		}
		if len(vars) <= optLen { // this is the last var
			if (remTsel != nil) && (remTselFound == false) {
				return false, incoming // remTsel was required
			}
			return true, nil // all ok
		}
		vars = vars[optLen:] // go to next var
	}
	return false, incoming
}

// validate a CC TPDU, or return the bit pattern of the rejected TPDU header
// up to and including the octet which caused the rejection.
// NOTE: it is legal to ignore the prefTpduSize parameter, even if it was
// present in the CR. It is illegal to have both tpduSize and prefTpduSize
// in a CC TPDU.
func validateCC(incoming []byte, crCv connVars) (bool, []byte) {
	// validate fixed part - dstref must be equal to the srcref of the CR
	ok, vars := validateFixed(incoming, crCv.srcRef[:], crCv.tpduSize > 0)
	if !ok || vars == nil {
		return ok, vars
	}
	index := connMinLen
	tpduSize := false
	prefTpduSize := false
	// decode the variable part
	for len(vars) > 2 {
		id := vars[0]
		optLen := int(vars[1]) + 2
		index += optLen
		if (len(vars) < optLen) || (optLen < 3) {
			return false, incoming // inconsistent option length
		}
		switch id {
		case locTselID:
			ok = bytes.Equal(vars[2:optLen], crCv.locTsel)
		case remTselID:
			ok = bytes.Equal(vars[2:optLen], crCv.remTsel)
		case tpduSizeID:
			ok = validCCTpduSize(vars, crCv, prefTpduSize)
			tpduSize = true
		case prefTpduSizeID:
			ok = validCCPrefTpduSize(vars, crCv, tpduSize)
			prefTpduSize = true
		case optionsID:
			ok = validCCOptions(vars, crCv)
		default:
			ok = false // unknown option
		}
		if !ok {
			return false, incoming[:index]
		}
		if len(vars) <= optLen { // this is the last var
			if (crCv.tpduSize > 0) && !tpduSize && !prefTpduSize {
				return false, incoming // tpduSize was required
			}
			return true, nil // all ok
		}
		vars = vars[optLen:] // go to next var
	}
	return false, incoming
}

// validate the fixed part of a CR or CC. If validation is ok, the variable
// part of the TPDU is returned, if present. Otherwise, the bit pattern of
// the rejected TPDU header up to and including the octet which caused the
// rejection is returned. If needVar is true, the TPDU is considered valid
// only if it has a variable part.
func validateFixed(incoming, dstRef []byte, needVar bool) (bool, []byte) {
	if !bytes.Equal(incoming[2:4], dstRef) {
		return false, incoming[:4]
	}
	if bytes.Equal(incoming[4:6], []byte{0x00, 0x00}) {
		return false, incoming[:6]
	}
	// calculate the length of fixed+variable part
	fixVarLen := incoming[0] + 1 // add the Length Indicator size (1 byte)
	userDataLen := len(incoming) - int(fixVarLen)
	if userDataLen < 0 {
		return false, incoming[:1] // invalid Length Indicator
	}
	if userDataLen > maxDataLen {
		return false, incoming
	}
	// see if there is a variable part
	if len(incoming) <= connMinLen {
		if needVar { // variable part required?
			return false, incoming
		}
		return true, nil // all ok
	}
	// all ok, discard the fixed part and user data (if present)
	return true, incoming[connMinLen:fixVarLen]
}

// validate the 'TPDU size' option of a CR packet
func validCRTpduSize(vars []byte) bool {
	optLen := int(vars[1])
	if optLen > tpduSizeLen {
		return false // invalid length
	}
	tpduSize := int8(vars[2])
	if (tpduSize < tpduSizeMin) || (tpduSize > tpduSizeMax) {
		return false // invalid size
	}
	return true
}

// validate the 'preferred TPDU size' option of a CR packet
func validCRPrefTpduSize(vars []byte) bool {
	optLen := int(vars[1])
	if optLen > prefTpduSizeLen {
		return false // invalid length
	}
	cv := connVars{prefTpduSize: vars[2 : optLen+2]}
	size := getMaxTpduSize(cv)
	if size < minTpduSize || size > defTpduSize {
		return false // invalid size
	}
	return true
}

// validate the 'Additional option selection' option of a CR packet
func validCROptions(vars []byte) bool {
	optLen := int(vars[1])
	if optLen > optionsLen {
		return false // invalid length
	}
	options := int8(vars[2])
	if (options < optionsMin) || (options > optionsMax) {
		return false // invalid options
	}
	return true
}

// validate the 'TPDU size' option of a CC packet
func validCCTpduSize(vars []byte, crCv connVars, prefTpduSize bool) bool {
	optLen := int(vars[1])
	tpduSize := vars[2]
	if optLen > tpduSizeLen {
		return false // invalid length
	}
	if (tpduSize < tpduSizeMin) || (tpduSize > tpduSizeMax) {
		return false // invalid size
	}
	ccCv := connVars{tpduSize: byte(tpduSize)}
	ccSize := getMaxTpduSize(ccCv)
	crSize := getMaxTpduSize(crCv)
	if ccSize > crSize {
		return false // invalid size
	}
	if prefTpduSize {
		return false
	}
	return true
}

// validate the 'preferred TPDU size' option of a CC packet
func validCCPrefTpduSize(vars []byte, crCv connVars, tpduSize bool) bool {
	optLen := int(vars[1])
	if optLen > prefTpduSizeLen {
		return false // invalid length
	}
	ccCv := connVars{prefTpduSize: vars[2 : optLen+2]}
	ccSize := getMaxTpduSize(ccCv)
	crSize := getMaxTpduSize(crCv)
	if ccSize > crSize || ccSize < minTpduSize {
		return false // invalid size
	}
	if crCv.prefTpduSize == nil {
		// illegal to use prefTpduSize if not used by CR
		return false
	}
	if tpduSize {
		return false
	}
	return true
}

// validate the 'Additional option selection' option of a CC packet
func validCCOptions(vars []byte, crCv connVars) bool {
	optLen := int(vars[1])
	if optLen > optionsLen {
		return false // invalid length
	}
	crOptions := int8(crCv.options)
	ccOptions := int8(vars[2])
	if (ccOptions < optionsMin) || (ccOptions > optionsMax) {
		return false // invalid options
	}
	if ccOptions > crOptions {
		return false // invalid options
	}
	return true
}

// validate a DT TPDU, or return the bit pattern of the rejected TPDU header
// up to and including the octet which caused the rejection.
func validateDT(incoming []byte, maxTpduSize int) (valid bool, erBuf []byte) {
	if len(incoming) > maxTpduSize {
		return false, incoming[:maxTpduSize+1]
	}
	if (incoming[eotIdx] == nrNonEot) || (incoming[eotIdx] == nrEot) {
		return true, nil
	}
	return false, incoming[:dtMinLen]
}

// validate an ED TPDU, or return the bit pattern of the rejected TPDU header
// up to and including the octet which caused the rejection.
func validateED(incoming []byte) (valid bool, erBuf []byte) {
	return validateDT(incoming, edMaxLen)
}

/* DR - Disconnect Request */
// the variable part of the DR TPDU can contain a parameter allowing
// additional information related to the clearing of the connection.
// This function is only used by test code.
func dr(conn TOSIConn, reason byte, info []byte) (tpdu []byte) {
	DST_REF := conn.dstRef[:]
	SRC_REF := conn.srcRef[:]
	fixed := append([]byte{drID}, DST_REF...)
	fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, reason)
	var variable []byte
	// construct the info option
	if info != nil {
		maxSize := conn.MaxTpduSize - drMinLen
		if maxSize < len(info) {
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
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isDR(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, drID, drMinLen)
}

// return info about the disconnection request
func getErrorDR(tpdu []byte) error {
	e := ProtocolError{msg: drReason[tpdu[drReasonIdx]]}
	if len(tpdu) > drInfoIdx {
		e.Info = tpdu[drInfoIdx:]
	}
	return &e
}

// returns the maximum TPDU size for a connection.
// According to RFC1006, the defaul value is 65531
// instead of 128.
func getMaxTpduSize(cv connVars) (size uint64) {
	if cv.tpduSize > 0 {
		size_shift := uint8(cv.tpduSize) - 7
		size = (minTpduSize << size_shift)
	} else {
		size = defTpduSize
	}
	if cv.prefTpduSize != nil {
		padding := make([]byte, 8-len(cv.prefTpduSize))
		paddedSize := append(padding, cv.prefTpduSize...)
		buf := bytes.NewBuffer(paddedSize)
		binary.Read(buf, binary.BigEndian, &size)
		size = size * minTpduSize
	}
	return
}

/* ER - Error */
// the variable part of the ER TPDU contains the bit pattern of the rejected TPDU
// header up to and including the octet which caused the rejection.
// This parameter is mandatory in class 0.
func er(dstRef []byte, cause byte, invalidTpdu []byte) (tpdu []byte) {
	DST_REF := dstRef
	fixed := append([]byte{erID}, DST_REF...)
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
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isER(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, erID, erMinLen)
}

// return info about the error occurred
func getErrorER(tpdu []byte) error {
	e := ProtocolError{msg: erCause[tpdu[erCauseIdx]]}
	if len(tpdu) > erInvIdx {
		e.Info = tpdu[erInvIdx:]
	}
	return &e
}

/* DT - Data Transfer */
func dt(userData []byte, endOfTsdu byte) (tpdu []byte) {
	tpdu = append([]byte{dtID}, endOfTsdu)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	tpdu = append(tpdu, userData...)
	return
}

// determine if a packet is a DT, and read its Length Indicator
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isDT(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, dtID, dtMinLen)
}

/* ED - Expedited Data. This is a non-standard TPDU defined in RFC 1006 */
/* It is equal to DT, just with a different ID */
func ed(userData []byte, endOfTsdu byte) (tpdu []byte) {
	tpdu = append([]byte{edID}, endOfTsdu)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	tpdu = append(tpdu, userData...)
	return
}

// determine if a packet is an ED, and read its Length Indicator
// in case of error tlen is the length of the input slice up to
// and including the faulty byte
func isED(incoming []byte) (found bool, tlen uint8) {
	return isType(incoming, edID, edMinLen)
}

// determine if a packet is of a certain type, and read its Length Indicator
// in case of error tlen is the length of the input slice up to and including
// the faulty byte
func isType(incoming []byte, id byte, minLen int) (bool, uint8) {
	if len(incoming) < minLen {
		return false, uint8(len(incoming))
	}
	if incoming[1] == id {
		return true, incoming[0]
	}
	return false, 2
}

/* create a TPKT from a TPDU */
func tpkt(tpdu []byte) (tpkt []byte) {
	header := []byte{tpktVrsn, tpktReserved}
	pLen := uint16(len(tpdu) + tpktHlen) // length includes this header too
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
	if incoming[0] == tpktVrsn {
		found = true
		buf := bytes.NewBuffer(incoming[2:4])
		err := binary.Read(buf, binary.BigEndian, &tlen)
		if err == nil && tlen > 0 {
			return
		}
	}
	return false, 0
}
