package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {

	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered from panic:", r)
		}
	}()

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

	buf := make([]byte, 4096) // 4KB buffer

	cache := NewDNSCache()
	cache.StartCleanup(5 * time.Minute)

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Failed to read from UDP:", err)
			continue
		}

		go func(clientAddr *net.UDPAddr, packet []byte) {
			responsePacket, err := handlePacket(packet, cache)
			if err != nil {
				log.Println("Failed to handle DNS packet:", err)
				return
			}

			fmt.Println(responsePacket)
			updatedPacket, err := responsePacket.ToBytes()
			if err != nil {
				log.Println("Failed to convert DNS packet to bytes:", err)
				return
			}

			_, err = udpConn.WriteToUDP(updatedPacket, clientAddr)
			if err != nil {
				log.Println("Failed to send response to client:", err)
			}
		}(clientAddr, buf[:n])
	}

}
