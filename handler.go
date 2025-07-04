package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

var RootServers = map[string][]net.IP{
	"A": {net.ParseIP("198.41.0.4"), net.ParseIP("2001:503:ba3e::2:30")},
	"B": {net.ParseIP("199.9.14.201"), net.ParseIP("2801:1b8:10::b")},
	"C": {net.ParseIP("192.33.4.12"), net.ParseIP("2001:500:2::c")},
	"D": {net.ParseIP("199.7.91.13"), net.ParseIP("2001:500:2d::d")},
	"E": {net.ParseIP("192.203.230.10"), net.ParseIP("2001:500:a8::e")},
	"F": {net.ParseIP("192.5.5.241"), net.ParseIP("2001:500:2f::f")},
	"G": {net.ParseIP("192.112.36.4"), net.ParseIP("2001:500:12::d0d")},
	"H": {net.ParseIP("198.97.190.53"), net.ParseIP("2001:500:1::53")},
	"I": {net.ParseIP("192.36.148.17"), net.ParseIP("2001:7fe::53")},
	"J": {net.ParseIP("192.58.128.30"), net.ParseIP("2001:503:c27::2:30")},
	"K": {net.ParseIP("193.0.14.129"), net.ParseIP("2001:7fd::1")},
	"L": {net.ParseIP("199.7.83.42"), net.ParseIP("2001:500:9f::42")},
	"M": {net.ParseIP("202.12.27.33"), net.ParseIP("2001:dc3::35")},
}

func handlePacket(queryBuffer []byte) (dns.DNSPacket, error) {
	dnsQuery, err := dns.ParseDNSPacket(queryBuffer, len(queryBuffer))
	if err != nil {
		log.Println("Failed to parse DNS packet:", err)
		return dns.DNSPacket{}, err
	}

	if dnsQuery.Header.QDCOUNT != 1 {
		return dns.DNSPacket{}, errors.New("Only one question supported") // We only handle single question queries
	}

	dnsServer := getRandomDNSServer(RootServers)

	responsePacket := dns.DNSPacket{Header: dnsQuery.Header}

	answers, err := resolve(dnsServer, dnsQuery.Questions[0].Domain, dnsQuery.Questions[0].Type)
	if err != nil {
		log.Println("Failed to resolve DNS query:", err)
		return dns.DNSPacket{}, err
	}

	responsePacket.Answers = answers

	for _, additionalRecord := range dnsQuery.Additional {
		if record, ok := additionalRecord.(dns.OPTRecord); ok {
			responsePacket.Additional = append(responsePacket.Additional, record)
		}
	}

	return responsePacket, nil
}

// queryOverTCP is used by the query function to handle truncated DNS responses over TCP.
func queryOverTCP(dnsServer net.IP, query dns.DNSPacket) ([]byte, error) {
	dnsServerAddr := &net.TCPAddr{
		IP:   dnsServer,
		Port: 53,
	}
	conn, err := net.DialTCP("tcp", nil, dnsServerAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	queryBuffer, err := query.ToBytes()
	if err != nil {
		return nil, err
	}

	queryLen := len(queryBuffer)
	queryPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(queryPrefix, uint16(queryLen))

	// Send the DNS request
	if _, err = conn.Write(append(queryPrefix, queryBuffer...)); err != nil {
		return nil, err
	}

	lenBuf := make([]byte, 2)
	// Read the length of the response
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	// Read the response
	response := make([]byte, respLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}

	return response, nil
}

func query(dnsServerAddr net.IP, query dns.DNSPacket) (*dns.DNSPacket, error) {

	// This function queries the DNS server using UDP.
	// In case if required it used TCP to query the DNS server.

	dnsServer := net.UDPAddr{
		IP:   dnsServerAddr,
		Port: 53,
	}

	var localAddress = &net.UDPAddr{
		IP:   net.IPv4zero, // Use any available local address
		Port: 0,            // Use any available local port
	}

	forwardConn, err := net.DialUDP("udp", localAddress, &dnsServer)
	if err != nil {
		log.Println("Failed to connect to DNS server:", err)
		return nil, err
	}

	defer forwardConn.Close()

	buf := make([]byte, 4096) // 4KB buffer
	serializedQuery, err := query.ToBytes()
	if err != nil {
		return nil, err
	}

	_, err = forwardConn.Write(serializedQuery)
	if err != nil {
		return nil, err
	}

	if err = forwardConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Println("Failed to set deadline on forward connection:", err)
	}

	n2, _, err := forwardConn.ReadFromUDP(buf)
	if err != nil {
		log.Println("Failed to read from forward connection:", err)
		return nil, err
	}

	parsedResponse, err := dns.ParseDNSPacket(buf[:n2], n2)
	if err != nil {
		if err.Error() == "Truncated DNS packet" {
			newPacketBytes, err := queryOverTCP(dnsServerAddr, query)
			if err != nil {
				log.Println("Error querying DNS server over TCP:", err)
				return nil, err
			}
			parsedResponse, err = dns.ParseDNSPacket(newPacketBytes, len(newPacketBytes))
			if err != nil {
				log.Println("Error parsing DNS packet:", err)
				return nil, err
			}
		} else {
			log.Println("Failed to parse DNS response:", err)
			return nil, err
		}
	}

	return parsedResponse, nil
}

func getRandomDNSServer(map[string][]net.IP) net.IP {
	keys := make([]string, 0, len(RootServers))
	for k := range RootServers {
		keys = append(keys, k)
	}
	randomKey := keys[rand.Intn(len(keys))]
	server := RootServers[randomKey]
	k := rand.Intn(len(server))
	for server[k].To4() == nil {
		k = rand.Intn(len(server))
	}
	return server[k]

	// return net.IP{1, 1, 1, 1} // Placeholder for a random DNS server IP
}

func resolve(dnsServer net.IP, domain string, recordType dns.RecordType) ([]dns.DNSRecord, error) {
	dnsQueryPacket := dns.DNSPacket{
		Header: dns.DNSHeader{
			ID:      uint16(rand.Intn(65536)), // Random ID for the DNS query
			QR:      0,                        // Query
			OPCODE:  0,                        // Standard query,
			RD:      1,                        // Recursion Desired
			QDCOUNT: 1,
		},
		Questions: []dns.DNSQuestion{
			{
				Domain: domain,
				Type:   recordType,
				Class:  dns.ClassType.IN, // Internet class
			},
		},
		Additional: []dns.DNSRecord{},
	}

	responsePacket, err := query(dnsServer, dnsQueryPacket)
	if err != nil {
		// Error -> QDCOUNT != len(questions)
		return nil, err
	}

	if responsePacket.Header.RCODE != dns.DNSResponseCodeType.NoError {
		err := RESCODEError{responsePacket.Header.RCODE}
		var dnsReecord []dns.DNSRecord = nil
		if responsePacket.Header.RCODE == dns.DNSResponseCodeType.NameError {
			// SOA
		}
		return dnsReecord, err
	}

	for _, answer := range responsePacket.Answers {
		if answer.Preamble().Type == recordType && answer.Preamble().Name == domain {
			return responsePacket.Answers, nil
		}
	}

	for _, answer := range responsePacket.Answers {
		if answer.Preamble().Type == dns.RType.CNAME {
			record := answer.(dns.CNAMERecord)
			cnameTarget := record.CanonicalName
			resolved, err := resolve(dnsServer, cnameTarget, dns.RType.CNAME)
			if err != nil {
				return nil, err
			}
			return append([]dns.DNSRecord{answer}, resolved...), nil
		}
	}

	nsServers := make(map[string][]net.IP)

	for _, nsRecord := range responsePacket.Authoratives {
		record := nsRecord.(dns.NSDNSRecord)
		nsServers[record.Host] = []net.IP{}
	}

	for _, additionalRecord := range responsePacket.Additional {
		switch record := additionalRecord.(type) {
		case dns.ADNSRecord:
			if ips, exists := nsServers[record.Name]; exists {
				nsServers[record.Name] = append(ips, record.IP)
			}
		case dns.AAAARecord:
			if ips, exists := nsServers[record.Name]; exists {
				nsServers[record.Name] = append(ips, record.IP)
			}
		}
	}

	responsePacket.Header.ANCOUNT = uint16(len(responsePacket.Answers))
	responsePacket.Header.NSCOUNT = uint16(len(responsePacket.Authoratives))
	responsePacket.Header.ARCOUNT = uint16(len(responsePacket.Additional))
	if len(nsServers) == 0 {
		log.Println("No nameservers found in response, using root servers")
		nsServers = RootServers
	}
	nextDNSServer := getRandomDNSServer(nsServers)
	return resolve(nextDNSServer, domain, recordType)
}
