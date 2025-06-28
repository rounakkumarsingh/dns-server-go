package dns

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
)

func encodeDomainName(name string, offsetMap map[string]uint, currentOffset uint) []byte {
	labels := strings.Split(name, ".")
	var buf []byte
	for i, label := range labels {
		suffix := strings.Join(labels[i:], ".")
		if pointer, ok := offsetMap[suffix]; ok {
			// If the domain name is already encoded, use a compression pointer
			offSet := 0xC000 | pointer
			pointerBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(pointerBytes, uint16(offSet))
			buf = append(buf, pointerBytes...)
			return buf
		}
		length := len(label)
		buf = append(buf, byte(length))
		buf = append(buf, []byte(label)...)
		offsetMap[suffix] = currentOffset
		currentOffset += uint(length + 1) // +1 for the length byte
	}
	buf = append(buf, 0) // end of domain
	return buf
}

func checkBits(value uint, numBits uint) bool {
	return value <= uint(math.Pow(2, float64(numBits)))
}

func decodeDomainName(encodedDomainName []byte, start int, jumped bool) (string, int, error) {
	var parts []string
	i := start
	for ; i < len(encodedDomainName) && encodedDomainName[i] != 0; i++ {
		partLength := uint(encodedDomainName[i])

		if partLength&0xC0 == 0xC0 {
			// This is a compression pointer to another compression pointer
			if jumped {
				return "", -1, errors.New("Invalid compression pointer to another compression pointer")
			}
			if i+1 >= len(encodedDomainName) {
				return "", -1, errors.New("Compression pointer out of bounds")
			}
			offset := int(binary.BigEndian.Uint16(encodedDomainName[i:i+2]) & 0x3FFF)
			if offset >= len(encodedDomainName) || offset < 0 {
				return "", -1, errors.New("Invalid compression pointer")
			}
			value, _, err := decodeDomainName(encodedDomainName, offset, true)
			if err != nil {
				return "", -1, err
			}
			parts = append(parts, value)
			return strings.Join(parts, "."), i + 1, nil
		}

		if i+int(partLength) >= len(encodedDomainName) {
			return "", -1, errors.New("Invalid Encoded Domain name")
		}
		part := encodedDomainName[i+1 : i+int(partLength)+1]
		parts = append(parts, string(part))
		i = i + int(partLength)
	}
	return strings.Join(parts, "."), i, nil
}
