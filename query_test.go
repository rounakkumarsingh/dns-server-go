package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/rounakkumarsingh/dns-server/dns"
)

// fakeNameserver listens on the same loopback port over UDP and TCP and
// points query at it. Each handler gets the parsed query and returns the
// packet to send back.
func fakeNameserver(t *testing.T, onUDP, onTCP func(q *dns.DNSPacket) dns.DNSPacket) {
	t.Helper()
	var udpConn *net.UDPConn
	var tcpListener *net.TCPListener
	for attempt := 0; ; attempt++ {
		var err error
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := udpConn.LocalAddr().(*net.UDPAddr).Port
		tcpListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			break
		}
		udpConn.Close()
		if attempt == 10 {
			t.Fatalf("could not get matching UDP and TCP ports: %v", err)
		}
	}
	t.Cleanup(func() { udpConn.Close(); tcpListener.Close() })

	original := upstreamPort
	upstreamPort = udpConn.LocalAddr().(*net.UDPAddr).Port
	t.Cleanup(func() { upstreamPort = original })

	reply := func(q *dns.DNSPacket, handler func(*dns.DNSPacket) dns.DNSPacket) []byte {
		response := handler(q)
		data, err := response.ToBytes()
		if err != nil {
			t.Errorf("fake nameserver: ToBytes: %v", err)
		}
		return data
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q, err := dns.ParseDNSPacket(buf[:n], n)
			if err != nil {
				t.Errorf("fake nameserver: parsing UDP query: %v", err)
				return
			}
			udpConn.WriteToUDP(reply(q, onUDP), addr)
		}
	}()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				conn.Close()
				continue
			}
			queryBuf := make([]byte, binary.BigEndian.Uint16(lenBuf))
			if _, err := io.ReadFull(conn, queryBuf); err != nil {
				conn.Close()
				continue
			}
			q, err := dns.ParseDNSPacket(queryBuf, len(queryBuf))
			if err != nil {
				t.Errorf("fake nameserver: parsing TCP query: %v", err)
				conn.Close()
				continue
			}
			data := reply(q, onTCP)
			conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(data))))
			conn.Write(data)
			conn.Close()
		}
	}()
}

func responseTo(q *dns.DNSPacket, answers ...dns.DNSRecord) dns.DNSPacket {
	return dns.DNSPacket{
		Header:    dns.DNSHeader{ID: q.Header.ID, QR: 1, AA: 1, QDCOUNT: 1, ANCOUNT: uint16(len(answers))},
		Questions: q.Questions,
		Answers:   answers,
	}
}

func testQuery(domain string) dns.DNSPacket {
	return dns.DNSPacket{
		Header:    dns.DNSHeader{ID: 0x5151, RD: 1, QDCOUNT: 1},
		Questions: []dns.DNSQuestion{{Domain: domain, Type: dns.RType.A, Class: dns.ClassType.IN}},
	}
}

func TestQueryFallsBackToTCPWhenTruncated(t *testing.T) {
	fakeNameserver(t,
		func(q *dns.DNSPacket) dns.DNSPacket {
			r := responseTo(q)
			r.Header.TC = 1
			return r
		},
		func(q *dns.DNSPacket) dns.DNSPacket {
			return responseTo(q, dns.ADNSRecord{DNSRecordPreamble: preamble("big.example.", dns.RType.A, 60), IP: net.IPv4(7, 7, 7, 7).To4()})
		},
	)

	response, err := query(net.IPv4(127, 0, 0, 1), testQuery("big.example."))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(response.Answers) != 1 {
		t.Fatalf("expected the TCP answer, got %v", response.Answers)
	}
}

func TestQueryRejectsMismatchedResponse(t *testing.T) {
	tests := map[string]func(q *dns.DNSPacket) dns.DNSPacket{
		"wrong ID": func(q *dns.DNSPacket) dns.DNSPacket {
			r := responseTo(q)
			r.Header.ID++
			return r
		},
		"wrong question": func(q *dns.DNSPacket) dns.DNSPacket {
			r := responseTo(q)
			r.Questions = []dns.DNSQuestion{{Domain: "evil.example.", Type: dns.RType.A, Class: dns.ClassType.IN}}
			return r
		},
		"not a response": func(q *dns.DNSPacket) dns.DNSPacket {
			r := responseTo(q)
			r.Header.QR = 0
			return r
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			fakeNameserver(t, handler, handler)
			if _, err := query(net.IPv4(127, 0, 0, 1), testQuery("ok.example.")); err == nil {
				t.Error("expected query to reject the response")
			}
		})
	}
}

func TestQueryAcceptsQuestionInDifferentCase(t *testing.T) {
	handler := func(q *dns.DNSPacket) dns.DNSPacket {
		r := responseTo(q)
		r.Questions = []dns.DNSQuestion{{Domain: strings.ToUpper(q.Questions[0].Domain), Type: dns.RType.A, Class: dns.ClassType.IN}}
		return r
	}
	fakeNameserver(t, handler, handler)
	if _, err := query(net.IPv4(127, 0, 0, 1), testQuery("mixed.example.")); err != nil {
		t.Errorf("query: %v", err)
	}
}
