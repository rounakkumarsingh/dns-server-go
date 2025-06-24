package dns

import "errors"

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

	for _, question := range m.Questions {
		buf = append(buf, question.ToBytes()...)
	}

	if m.Header.ANCOUNT != uint16(len(m.Answers)) {
		return nil, errors.New("the number of answers is not same as ANCOUNT in header")
	}

	for _, answer := range m.Answers {
		buf = append(buf, answer.ToBytes()...)
	}

	for _, authoratives := range m.Authoratives {
		buf = append(buf, authoratives.ToBytes()...)
	}

	for _, additional := range m.Additional {
		buf = append(buf, additional.ToBytes()...)
	}

	return buf, nil
}
