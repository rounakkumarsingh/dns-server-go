package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

func preamble(name string, rtype dns.RecordType, ttl uint32) dns.DNSRecordPreamble {
	return dns.DNSRecordPreamble{Name: name, Type: rtype, Class: dns.ClassType.IN, TTL: ttl}
}

func testSOA(zone string) dns.SOARecord {
	return dns.SOARecord{
		DNSRecordPreamble: preamble(zone, dns.RType.SOA, 3600),
		MName:             "ns1." + zone,
		RName:             "hostmaster." + zone,
		Serial:            1,
		Refresh:           7200,
		Retry:             900,
		Expire:            1209600,
		MinimumTTL:        300,
	}
}

// fakeUpstream replaces sendQuery with canned responses keyed by "name type"
// and counts how many upstream queries were made.
func fakeUpstream(t *testing.T, responses map[string]*dns.DNSPacket) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	original := sendQuery
	sendQuery = func(_ net.IP, q dns.DNSPacket) (*dns.DNSPacket, error) {
		calls.Add(1)
		key := fmt.Sprintf("%s %s", q.Questions[0].Domain, q.Questions[0].Type)
		response, ok := responses[key]
		if !ok {
			return nil, fmt.Errorf("unexpected upstream query: %s", key)
		}
		return response, nil
	}
	t.Cleanup(func() { sendQuery = original })
	return &calls
}

func queryBytes(t *testing.T, domain string, rtype dns.RecordType) []byte {
	t.Helper()
	q := dns.DNSPacket{
		Header:    dns.DNSHeader{ID: 0x4242, RD: 1, QDCOUNT: 1},
		Questions: []dns.DNSQuestion{{Domain: domain, Type: rtype, Class: dns.ClassType.IN}},
	}
	data, err := q.ToBytes()
	if err != nil {
		t.Fatalf("building query: %v", err)
	}
	return data
}

func TestResolveNoDataReturnsSOA(t *testing.T) {
	// NOERROR with no answers and an SOA (not NS) in the authority section.
	fakeUpstream(t, map[string]*dns.DNSPacket{
		"example.com. AAAA": {
			Header:       dns.DNSHeader{QR: 1, AA: 1, RCODE: dns.DNSResponseCodeType.NoError},
			Authoratives: []dns.DNSRecord{testSOA("example.com.")},
		},
	})

	answers, soaRecords, err := resolve(net.IPv4(127, 0, 0, 1), "example.com.", dns.RType.AAAA, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(answers) != 0 {
		t.Errorf("expected no answers, got %v", answers)
	}
	if len(soaRecords) != 1 {
		t.Errorf("expected 1 SOA record, got %d", len(soaRecords))
	}
}

func TestResolveFollowsCNAMEToAnotherZone(t *testing.T) {
	fakeUpstream(t, map[string]*dns.DNSPacket{
		"www.example.com. A": {
			Header: dns.DNSHeader{QR: 1, AA: 1},
			Answers: []dns.DNSRecord{
				dns.CNAMERecord{DNSRecordPreamble: preamble("www.example.com.", dns.RType.CNAME, 300), CanonicalName: "edge.cdn.net."},
			},
		},
		"edge.cdn.net. A": {
			Header: dns.DNSHeader{QR: 1, AA: 1},
			Answers: []dns.DNSRecord{
				dns.ADNSRecord{DNSRecordPreamble: preamble("edge.cdn.net.", dns.RType.A, 60), IP: net.IPv4(5, 6, 7, 8).To4()},
			},
		},
	})

	answers, _, err := resolve(net.IPv4(127, 0, 0, 1), "www.example.com.", dns.RType.A, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("expected CNAME + A, got %v", answers)
	}
	if _, ok := answers[0].(dns.CNAMERecord); !ok {
		t.Errorf("answers[0] = %T, want CNAMERecord", answers[0])
	}
	if a, ok := answers[1].(dns.ADNSRecord); !ok || !a.IP.Equal(net.IPv4(5, 6, 7, 8)) {
		t.Errorf("answers[1] = %v, want A 5.6.7.8", answers[1])
	}
}

func TestResolveFollowsCNAMEChainInSameResponse(t *testing.T) {
	calls := fakeUpstream(t, map[string]*dns.DNSPacket{
		"www.example.com. A": {
			Header: dns.DNSHeader{QR: 1, AA: 1},
			Answers: []dns.DNSRecord{
				dns.CNAMERecord{DNSRecordPreamble: preamble("www.example.com.", dns.RType.CNAME, 300), CanonicalName: "a.example.com."},
				dns.CNAMERecord{DNSRecordPreamble: preamble("a.example.com.", dns.RType.CNAME, 300), CanonicalName: "b.example.com."},
				dns.ADNSRecord{DNSRecordPreamble: preamble("b.example.com.", dns.RType.A, 60), IP: net.IPv4(9, 9, 9, 9).To4()},
			},
		},
	})

	answers, _, err := resolve(net.IPv4(127, 0, 0, 1), "www.example.com.", dns.RType.A, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(answers) != 3 {
		t.Fatalf("expected 3 records, got %v", answers)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 upstream query, got %d", calls.Load())
	}
}

func TestHandlePacketNoDataResponse(t *testing.T) {
	fakeUpstream(t, map[string]*dns.DNSPacket{
		"example.com. AAAA": {
			Header:       dns.DNSHeader{QR: 1, AA: 1},
			Authoratives: []dns.DNSRecord{testSOA("example.com.")},
		},
	})

	response, err := handlePacket(queryBytes(t, "example.com.", dns.RType.AAAA), NewDNSCache())
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if response.Header.RCODE != dns.DNSResponseCodeType.NoError {
		t.Errorf("RCODE = %v, want NoError", response.Header.RCODE)
	}
	if response.Header.ANCOUNT != 0 || response.Header.NSCOUNT != 1 {
		t.Errorf("ANCOUNT/NSCOUNT = %d/%d, want 0/1", response.Header.ANCOUNT, response.Header.NSCOUNT)
	}
	if _, err := response.ToBytes(); err != nil {
		t.Errorf("ToBytes: %v", err)
	}
}

func TestHandlePacketCachesNXDOMAIN(t *testing.T) {
	calls := fakeUpstream(t, map[string]*dns.DNSPacket{
		"missing.example.com. A": {
			Header:       dns.DNSHeader{QR: 1, AA: 1, RCODE: dns.DNSResponseCodeType.NameError},
			Authoratives: []dns.DNSRecord{testSOA("example.com.")},
		},
	})
	cache := NewDNSCache()
	query := queryBytes(t, "missing.example.com.", dns.RType.A)

	for i := range 2 {
		response, err := handlePacket(query, cache)
		if err != nil {
			t.Fatalf("handlePacket #%d: %v", i+1, err)
		}
		if response.Header.RCODE != dns.DNSResponseCodeType.NameError {
			t.Errorf("#%d: RCODE = %v, want NameError", i+1, response.Header.RCODE)
		}
		if len(response.Authoratives) != 1 {
			t.Errorf("#%d: expected SOA in authority section, got %v", i+1, response.Authoratives)
		}
		if _, err := response.ToBytes(); err != nil {
			t.Errorf("#%d: ToBytes: %v", i+1, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("expected second NXDOMAIN lookup to be served from cache, got %d upstream queries", calls.Load())
	}
}

func TestServeGivesEachHandlerItsOwnPacket(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	// The first handler doesn't read its packet until the second packet has
	// been received into the shared read buffer.
	secondReceived := make(chan struct{})
	var calls atomic.Int32
	go serve(serverConn, func(packet []byte) ([]byte, error) {
		switch calls.Add(1) {
		case 1:
			<-secondReceived
		case 2:
			close(secondReceived)
		}
		if string(packet) == "panic" {
			panic("boom")
		}
		return append([]byte(nil), packet...), nil
	})

	client, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, msg := range []string{"first", "2nd"} {
		if _, err := client.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		if msg == "first" {
			// Make sure "first" is read before "2nd" is sent.
			for calls.Load() < 1 {
				time.Sleep(time.Millisecond)
			}
		}
	}
	buf := make([]byte, 64)
	for range 2 {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("reading response: %v", err)
		}
		got[string(buf[:n])] = true
	}
	if !got["first"] || !got["2nd"] {
		t.Errorf("responses = %v, want both %q and %q", got, "first", "2nd")
	}

	// A panicking handler must not take the server down.
	if _, err := client.Write([]byte("panic")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "alive" {
		t.Errorf("after panic got %q, %v; want %q", buf[:n], err, "alive")
	}
}
