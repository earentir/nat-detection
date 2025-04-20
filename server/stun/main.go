package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/earentir/nat-detection/internal/stun"
)

func main() {
	pc, err := net.ListenPacket("udp", ":3478")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("STUN server listening on :3478 (dual‑stack)")

	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Println("read:", err)
			continue
		}
		ip := addr.(*net.UDPAddr).IP
		port := addr.(*net.UDPAddr).Port

		// Parse header quickly to see if Binding Request
		if n < 20 || buf[1] != 0x01 { // second byte lower 8 bits of type==1
			continue
		}
		var id [12]byte
		copy(id[:], buf[8:20])

		res := stun.BuildBindingRequest(id) // reuse builder for header
		// overwrite STUN type to 0x0101 (Binding Success) and add XOR‑MAP attr
		res[0] = 0x01
		res[1] = 0x01
		attr := buildXORAttr(ip, port)
		binary.BigEndian.PutUint16(res[2:4], uint16(len(attr))) // new len
		res = append(res, attr...)

		if _, err := pc.WriteTo(res, addr); err != nil {
			log.Println("write:", err)
		}
	}
}

func buildXORAttr(ip net.IP, port int) []byte {
	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR‑MAPPED‑ADDRESS
	if ip.To4() != nil {
		binary.BigEndian.PutUint16(attr[2:4], 8)
		attr = append(attr, 0, 1)                       // RSV, fam v4
		binary.BigEndian.PutUint16(attr[len(attr):], 0) // pad
		attr = attr[:len(attr)+2]
		binary.BigEndian.PutUint16(attr[len(attr)-2:], uint16(port)^0x2112)
		mc := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			attr = append(attr, ip[i]^mc[i])
		}
	} else {
		binary.BigEndian.PutUint16(attr[2:4], 20)
		attr = append(attr, 0, 2) // RSV, fam v6
		binary.BigEndian.PutUint16(attr[len(attr):], 0)
		attr = attr[:len(attr)+2]
		binary.BigEndian.PutUint16(attr[len(attr)-2:], uint16(port)^0x2112)
		mc := make([]byte, 16)
		binary.BigEndian.PutUint32(mc, 0x2112A442)
		for i := 0; i < 16; i++ {
			attr = append(attr, ip[i]^mc[i%4])
		}
	}
	// 32‑bit pad not needed (already aligned)
	return attr
}
