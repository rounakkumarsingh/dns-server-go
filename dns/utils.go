package dns

import (
	"errors"
	"math"
	"strings"
)

func encodeDomainName(name string) []byte {
	parts := strings.Split(name, ".")
	var buf []byte
	for _, part := range parts {
		length := len(part)
		buf = append(buf, byte(length))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // end of domain
	return buf
}

func checkBits(value uint, numBits uint) bool {
	return value <= uint(math.Pow(2, float64(numBits)))
}

func decodeDomainName(encodedDomainName []byte) (string, int, error) {
	var parts []string
	i := 0
	for ; i < len(encodedDomainName) && encodedDomainName[i] != 0; i++ {
		partLength := uint(encodedDomainName[i])
		if i+int(partLength)+1 >= len(encodedDomainName) {
			return "", -1, errors.New("Invalid Encoded Domain name")
		}
		part := encodedDomainName[i+1 : i+int(partLength)+1]
		parts = append(parts, string(part))
		i = i + int(partLength)
	}
	return strings.Join(parts, "."), i, nil
}
