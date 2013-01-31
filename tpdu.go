package tosi

import (
	"bytes"
	"encoding/binary"
)

const (
	TpktHlen = 4
	// CR-related defs
	CRMinLen = 7
	CRid = 0xe0
	// CC-related defs
	CCMinLen = 7
	CCid = 0xd0
	// DT-related defs 
	DTMinLen = 3
	DT_ROA = 0xf0
)

/* CR - Connection Request */
// the variable part of the CR TPDU can contain the Transport-Selector, 
// maximum TPDU size, and preferred maximum TPDU size.
func CR(locTsel, remTsel int, tpduSize int8) (tpdu []byte) {
	DST_REF := []byte{0x00, 0x00}
	SRC_REF := []byte{0x00, 0x00}
        CLASS_OPTION := []byte{0x00}
	fixed := append([]byte{CRid}, DST_REF...)
        fixed = append(fixed, SRC_REF...)
	fixed = append(fixed, CLASS_OPTION...)
	TSEL := []byte{0xc2, 0x04, 0x00, 0x00, 0x00, 0x64}
	variable := TSEL
	tpdu = append(fixed, variable...)
	pLen := byte(len(tpdu))
	tpdu = append([]byte{pLen}, tpdu...)
	return 
}

func IsCR(incoming []byte) (found bool, tlen uint8) {
	if len(incoming) < CRMinLen {
                return false, 0
        }
	if (incoming[1] & 0xf0) == CRid {
		found = true
		buf := bytes.NewBuffer(incoming[0:1])
		err := binary.Read(buf, binary.BigEndian, &tlen)
		if err == nil {
                        return
                }
        }
        return false, 0
}

/* CC - Connection Confirm */
func CC() (tpdu []byte) {
	DST_REF := []byte{0x00, 0x00}
	SRC_REF := []byte{0x00, 0x00}
        CLASS_OPTION := []byte{0x00}
	fixed := append([]byte{CCid}, DST_REF...)
        fixed = append(fixed, SRC_REF...)
        fixed = append(fixed, CLASS_OPTION...)
        variable := []byte{}
	tpdu = append(fixed, variable...)
        pLen := byte(len(tpdu))
        tpdu = append([]byte{pLen}, tpdu...)
        return
}

func IsCC(incoming []byte) (found bool, tlen uint8) {
	if len(incoming) < CCMinLen {
                return false, 0
        }
	if (incoming[1] & 0xf0) == CCid {
		found = true
		buf := bytes.NewBuffer(incoming[0:1])
		err := binary.Read(buf, binary.BigEndian, &tlen)
		if err == nil {
                        return
                }
        }
        return false, 0
}

/* DT - Data Transfer */
func DT(userData []byte) (tpdu []byte) {
	var NR_EOT byte = 0x80
	tpdu = append([]byte{DT_ROA}, NR_EOT)
        pLen := byte(len(tpdu))
        tpdu = append([]byte{pLen}, tpdu...)
	tpdu = append(tpdu, userData...)
        return
}

func IsDT(incoming []byte) (found bool, tlen uint8) {
	if len(incoming) < DTMinLen {
                return false, 0
        }
	if (incoming[1]) == DT_ROA {
		found = true
		buf := bytes.NewBuffer(incoming[0:1])
		err := binary.Read(buf, binary.BigEndian, &tlen)
		if err == nil {
                        return
                }
        }
        return false, 0
}

/* create a TPKT from a TPDU */
func TPKT(tpdu []byte) (tpkt []byte) {
	header := []byte{0x03, 0x00}
	// length includes this header too
        pLen := len(tpdu) + 4
	pLen_MSB := pLen >> 8
	pLen_LSB := pLen - pLen_MSB
        header = append(header, byte(pLen_MSB), byte(pLen_LSB))
	tpkt = append(header, tpdu...)
	return
}

func IsTPKT(incoming []byte) (found bool, tlen uint16) {
	if len(incoming) < TpktHlen {
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