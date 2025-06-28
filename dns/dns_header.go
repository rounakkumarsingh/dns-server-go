package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSHeader struct {
	ID      uint16          // 16 bits ID
	QR      uint8           // 1 bit Response(1) or Query(0)
	OPCODE  uint8           // 4 bits represents the kind of query
	AA      uint8           // 1 bit Authoritative Answer
	TC      uint8           // 1 bit TrunCation
	RD      uint8           // 1 bit Recursion Desired
	RA      uint8           // 1 bit Recursion Available
	Z       uint8           // 1 bit
	AD      uint8           // 1 bit Authentic Data
	CD      uint8           // 1 bit Checking Disabled
	RCODE   DNSResponseCode // 4 bits Response Code(Server use)
	QDCOUNT uint16          // 16 bits number of Questions
	ANCOUNT uint16          // 16 bits number of Answers Records
	NSCOUNT uint16          // 16 bits number of Name Servers in Authority Records
	ARCOUNT uint16          // 16 bits number of Additional Records
}

func (h *DNSHeader) ToBytes() ([]byte, error) {

	if !checkBits(uint(h.ID), 16) {
		return nil, fmt.Errorf("ID is way too large in the header body")
	}
	if !checkBits(uint(h.QR), 1) {
		return nil, fmt.Errorf("QR is way too large in the header body")
	}
	if !checkBits(uint(h.OPCODE), 4) {
		return nil, fmt.Errorf("OPCODE is way too large in the header body")
	}
	if !checkBits(uint(h.AA), 1) {
		return nil, fmt.Errorf("AA is way too large in the header body")
	}
	if !checkBits(uint(h.TC), 1) {
		return nil, fmt.Errorf("TC is way too large in the header body")
	}
	if !checkBits(uint(h.RD), 1) {
		return nil, fmt.Errorf("RD is way too large in the header body")
	}
	if !checkBits(uint(h.RA), 1) {
		return nil, fmt.Errorf("RA is way too large in the header body")
	}
	if !checkBits(uint(h.Z), 1) {
		return nil, fmt.Errorf("Z is way too large in the header body")
	}
	if !checkBits(uint(h.AD), 1) {
		return nil, fmt.Errorf("AD is way too large in the header body")
	}
	if !checkBits(uint(h.CD), 1) {
		return nil, fmt.Errorf("CD is way too large in the header body")
	}
	if !checkBits(uint(h.RCODE), 4) {
		return nil, fmt.Errorf("RCODE is way too large in the header body")
	}
	if !checkBits(uint(h.QDCOUNT), 16) {
		return nil, fmt.Errorf("QDCOUNT is way too large in the header body")
	}
	if !checkBits(uint(h.ANCOUNT), 16) {
		return nil, fmt.Errorf("ANCOUNT is way too large in the header body")
	}
	if !checkBits(uint(h.NSCOUNT), 16) {
		return nil, fmt.Errorf("NSCOUNT is way too large in the header body")
	}
	if !checkBits(uint(h.ARCOUNT), 16) {
		return nil, fmt.Errorf("ARCOUNT is way too large in the header body")
	}

	b3 := (h.QR << 7) | ((h.OPCODE & 0xF) << 3) | (h.AA << 2) | (h.TC << 1) | h.RD
	b4 := (h.RA << 7) | (h.Z << 6) | (h.AD << 5) | (h.CD << 4) | (uint8(h.RCODE) & 0xF)

	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	buf[2] = b3
	buf[3] = b4
	binary.BigEndian.PutUint16(buf[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCOUNT)
	return buf, nil
}

func (h DNSHeader) String() string {
	qrType := "Query"
	if h.QR == 1 {
		qrType = "Response"
	}

	return fmt.Sprintf("DNS Header:\n"+
		"  ID: %d\n"+
		"  Type: %s\n"+
		"  OPCODE: %d\n"+
		"  Authoritative Answer: %t\n"+
		"  Truncated: %t\n"+
		"  Recursion Desired: %t\n"+
		"  Recursion Available: %t\n"+
		"  Response Code: %s\n"+
		"  Questions: %d\n"+
		"  Answers: %d\n"+
		"  Authority Records: %d\n"+
		"  Additional Records: %d",
		h.ID, qrType, h.OPCODE, h.AA == 1, h.TC == 1, h.RD == 1, h.RA == 1,
		h.RCODE, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT)
}
