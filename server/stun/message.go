package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
)

const (
	magic        = 0x2112A442
	typeBinding  = 0x0001
	attrXORMAP   = 0x0020
	headerSize   = 20
	transactionL = 12
)

// RandomTransactionID returns a cryptographically‑random 12‑byte value.
func RandomTransactionID() (id [transactionL]byte) {
	_, _ = rand.Read(id[:])
	return
}

// BuildBindingRequest returns a minimal STUN Binding Request.
func BuildBindingRequest(id [transactionL]byte) []byte {
	b := make([]byte, headerSize)
	binary.BigEndian.PutUint16(b[0:2], typeBinding)
	binary.BigEndian.PutUint16(b[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(b[4:8], magic)
	copy(b[8:], id[:])
	return b
}

// ParseXORMapped extracts the XOR‑MAPPED‑ADDRESS attribute from a STUN message.
func ParseXORMapped(raw []byte) (ip net.IP, port int, err error) {
	if len(raw) < headerSize {
		return nil, 0, errors.New("truncated")
	}
	if binary.BigEndian.Uint32(raw[4:8]) != magic {
		return nil, 0, errors.New("not STUN")
	}
	msgLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if len(raw) < headerSize+msgLen {
		return nil, 0, errors.New("bad length")
	}
	attrs := raw[headerSize : headerSize+msgLen]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+alen {
			break
		}
		val := attrs[4 : 4+alen]
		if typ == attrXORMAP {
			if len(val) < 4 {
				return nil, 0, errors.New("short XOR‑MAP")
			}
			fam := val[1]
			xport := binary.BigEndian.Uint16(val[2:4]) ^ uint16(magic>>16)
			switch fam {
			case 0x01: // IPv4
				if len(val) < 8 {
					return nil, 0, errors.New("short v4")
				}
				xip := make(net.IP, 4)
				mc := []byte{0x21, 0x12, 0xA4, 0x42}
				for i := 0; i < 4; i++ {
					xip[i] = val[4+i] ^ mc[i]
				}
				return xip, int(xport), nil
			case 0x02: // IPv6
				if len(val) < 20 {
					return nil, 0, errors.New("short v6")
				}
				xip := make(net.IP, 16)
				mc := make([]byte, 16)
				binary.BigEndian.PutUint32(mc[0:4], magic)
				for i := 0; i < 16; i++ {
					xip[i] = val[4+i] ^ mc[i%4]
				}
				return xip, int(xport), nil
			}
		}
		pad := (4 - (alen & 3)) & 3
		attrs = attrs[4+alen+pad:]
	}
	return nil, 0, errors.New("no XOR‑MAP")
}
