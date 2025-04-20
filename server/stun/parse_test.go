package stun

import (
	"encoding/binary"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	tid := RandomTransactionID()
	req := BuildBindingRequest(tid)
	if len(req) != 20 {
		t.Fatalf("req len=%d", len(req))
	}
	// fake success response (embed XOR‑MAPPED‑ADDRESS attr)
	res := make([]byte, 32)
	copy(res, req)
	binary.BigEndian.PutUint16(res[0:2], 0x0101) // Binding success
	binary.BigEndian.PutUint16(res[2:4], 12)     // length
	// attr header
	binary.BigEndian.PutUint16(res[20:22], attrXORMAP)
	binary.BigEndian.PutUint16(res[22:24], 8)
	// value: v4, port 0x4321 ^ cookie hi, IP 1.2.3.4 ^ cookie
	res[24] = 0 // rsv
	res[25] = 1 // fam v4
	binary.BigEndian.PutUint16(res[26:28], 0x4321^0x2112)
	ip := []byte{1, 2, 3, 4}
	mc := []byte{0x21, 0x12, 0xA4, 0x42}
	for i := 0; i < 4; i++ {
		res[28+i] = ip[i] ^ mc[i]
	}
	gotIP, gotPort, err := ParseXORMapped(res)
	if err != nil {
		t.Fatal(err)
	}
	if gotPort != 0x4321 || !gotIP.Equal(ip) {
		t.Fatalf("unexpected %v:%d", gotIP, gotPort)
	}
}
