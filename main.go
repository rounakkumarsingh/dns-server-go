package main

import (
	"fmt"
	"log"
	"net"
)

func main() {

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

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Failed to read from UDP:", err)
			continue
		}

		responsePacket, err := handlePacket(buf[:n])
		if err != nil {
			log.Println("Failed to handle DNS packet:", err)
			continue
		}

		fmt.Println(responsePacket)
		updatedPacket, err := responsePacket.ToBytes()
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
