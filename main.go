package main

import (
	"log"
	"net"

	"github.com/rounakkumarsingh/dns-server/dns"
)

func main() {

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
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

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Error receiving data:", err)
			break
		}

		log.Printf("% x\n", buf[:size])
		requestPacket, err := dns.ParseDNSPacket(buf, size, source)
		if err != nil {
			log.Println("Failed to parse DNS packet:", err)
			continue
		}
		log.Printf("%+v\n", requestPacket)

		responsePacket, err := dns.HandleDNSRequest(requestPacket)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		log.Printf("%+v\n", responsePacket)

		response, err := responsePacket.ToBytes()
		if err != nil {
			log.Println(err.Error())
			continue
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			log.Println("Failed to send response:", err)
		}
	}
}
