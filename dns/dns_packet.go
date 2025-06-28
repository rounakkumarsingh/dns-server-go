package dns

import (
	"errors"
	"fmt"
)

type DNSPacket struct {
	Header       DNSHeader
	Questions    []DNSQuestion
	Answers      []DNSRecord
	Authoratives []DNSRecord
	Additional   []DNSRecord
}

func (m *DNSPacket) ToBytes() ([]byte, error) {
	buf, err := m.Header.ToBytes()
	if err != nil {
		return nil, err
	}

	if m.Header.QDCOUNT != uint16(len(m.Questions)) {
		return nil, errors.New("the number of questions is not same as QDCOUNT in header")
	}

	var offsetMap = make(map[string]uint)

	for _, question := range m.Questions {
		buf = append(buf, question.ToBytes(offsetMap, uint(len(buf)))...)
	}

	if m.Header.ANCOUNT != uint16(len(m.Answers)) {
		return nil, errors.New("the number of answers is not same as ANCOUNT in header")
	}

	for _, answer := range m.Answers {
		buf = append(buf, answer.ToBytes(offsetMap, uint(len(buf)))...)
	}

	if m.Header.NSCOUNT != uint16(len(m.Authoratives)) {
		return nil, errors.New("the number of authoratives is not same as NSCOUNT in header")
	}

	for _, authoratives := range m.Authoratives {
		buf = append(buf, authoratives.ToBytes(offsetMap, uint(len(buf)))...)
	}

	if m.Header.ARCOUNT != uint16(len(m.Additional)) {
		return nil, errors.New("the number of additional records is not same as ARCOUNT in header")
	}

	for _, additional := range m.Additional {
		buf = append(buf, additional.ToBytes(offsetMap, uint(len(buf)))...)
	}

	return buf, nil
}

func (m *DNSPacket) String() string {
	result := fmt.Sprintf("DNS Packet:\n%s\n", m.Header.String())

	if len(m.Questions) > 0 {
		result += "\nQuestions:\n"
		for i, question := range m.Questions {
			result += fmt.Sprintf("  [%d] %s\n", i, question.String())
		}
	}

	if len(m.Answers) > 0 {
		result += "\nAnswers:\n"
		for i, answer := range m.Answers {
			result += fmt.Sprintf("  [%d] %s\n", i, answer.String())
		}
	}

	if len(m.Authoratives) > 0 {
		result += "\nAuthority Records:\n"
		for i, auth := range m.Authoratives {
			result += fmt.Sprintf("  [%d] %s\n", i, auth.String())
		}
	}

	if len(m.Additional) > 0 {
		result += "\nAdditional Records:\n"
		for i, add := range m.Additional {
			result += fmt.Sprintf("  [%d] %s\n", i, add.String())
		}
	}

	return result
}
