package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

func main() {
	// For stub resolver
	dnsServerAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		log.Println("Failed to resolve DNS server address:", err)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", ":1053")
	if err != nil {
		log.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	// Prepare buffer and set timeout
	buf := make([]byte, 512)

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Failed to read from UDP:", err)
			continue
		}

		forwardConn, err := net.DialUDP("udp", nil, dnsServerAddr)
		if err != nil {
			log.Println("Failed to connect to DNS server:", err)
			continue
		}

		recievedPacket, err := dns.ParseDNSPacket(buf[:n], n, clientAddr)
		if err != nil {
			log.Println("Failed to parse DNS packet:", err)
			forwardConn.Close()
			continue
		}

		fmt.Println("Received ", *recievedPacket)

		_, err = forwardConn.Write(buf[:n])
		if err != nil {
			log.Println("Failed to forward DNS request:", err)
			continue
		}

		if err = forwardConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			log.Println("Failed to set deadline on forward connection:", err)
		}

		n2, _, err := forwardConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Failed to read from forward connection:", err)
			continue
		}
		forwardConn.Close()

		parsedPacket, err := dns.ParseDNSPacket(buf[:n2], n2, clientAddr)
		if err != nil {
			log.Println("Failed to parse DNS packet:", err)
			continue
		}

		parsedPacket.Header.RA = 1 // Set Recursion Available flag
		parsedPacket.Header.RD = 1 // Set Recursion Desired flag

		fmt.Println("Received DNS packet:", parsedPacket)
		updatedPacket, err := parsedPacket.ToBytes()
		if err != nil {
			log.Println("Failed to convert DNS packet to bytes:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(updatedPacket, clientAddr)
		if err != nil {
			log.Println("Failed to send response to client:", err)
			continue
		}
	}

}
