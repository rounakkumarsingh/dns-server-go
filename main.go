package main

import (
	"errors"
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

	cache := NewDNSCache()
	cache.StartCleanup(5 * time.Minute)

	serve(udpConn, func(packet []byte) ([]byte, error) {
		responsePacket, err := handlePacket(packet, cache)
		if err != nil {
			return nil, err
		}

		fmt.Println(responsePacket)
		return responsePacket.ToBytes()
	})
}

// serve reads queries from udpConn and answers each one in its own goroutine.
// handle receives a private copy of the query, so it is safe to use after the
// read buffer has been reused for the next packet.
func serve(udpConn *net.UDPConn, handle func(packet []byte) ([]byte, error)) {
	buf := make([]byte, 4096) // 4KB buffer

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Println("Failed to read from UDP:", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go func(clientAddr *net.UDPAddr, packet []byte) {
			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered from panic while handling packet:", r)
				}
			}()

			response, err := handle(packet)
			if err != nil {
				log.Println("Failed to handle DNS packet:", err)
				return
			}

			_, err = udpConn.WriteToUDP(response, clientAddr)
			if err != nil {
				log.Println("Failed to send response to client:", err)
			}
		}(clientAddr, packet)
	}
}
