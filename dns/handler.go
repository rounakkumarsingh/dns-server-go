package dns

import "fmt"

func HandleDNSRequest(req *DNSPacket) (*DNSPacket, error) {
	RCODE := uint8(0)
	if req.Header.OPCODE != 0 {
		RCODE = 4
	}

	h := req.Header

	if h.QR != 0 {
		return nil, fmt.Errorf("invalid: not a query")
	}
	if h.OPCODE != 0 {
		return nil, fmt.Errorf("unsupported opcode %d", h.OPCODE)
	}
	if h.Z != 0 {
		return nil, fmt.Errorf("reserved Z field must be 0")
	}
	if h.QDCOUNT < 1 || len(req.Questions) != int(h.QDCOUNT) {
		return nil, fmt.Errorf("question count mismatch or empty")
	}

	answers := make([]DNSRecord, 0)
	authoratives := make([]DNSRecord, 0)
	additionals := make([]DNSRecord, 0)

	for _, question := range req.Questions {
		answer := getAnswerRecords(question)
		answers = append(answers, answer...)

		authorative := getAuthorativeRecords(question)
		authoratives = append(authoratives, authorative...)

		additional := getAdditionalRecords(question)
		additionals = append(additionals, additional...)
	}

	return &DNSPacket{
		Header: DNSHeader{
			ID:      req.Header.ID,
			QR:      1,
			OPCODE:  req.Header.OPCODE,
			AA:      0,
			TC:      0,
			RD:      req.Header.RD,
			RA:      0,
			Z:       0,
			AD:      0, // 1 after implementing DNSSEC
			CD:      req.Header.CD,
			RCODE:   RCODE,
			QDCOUNT: req.Header.QDCOUNT,
			ANCOUNT: uint16(len(answers)),
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions:    req.Questions,
		Answers:      answers,
		Authoratives: authoratives,
		Additional:   additionals,
	}, nil
}

func getAnswerRecords(q DNSQuestion) []DNSRecord      { return []DNSRecord{} }
func getAuthorativeRecords(q DNSQuestion) []DNSRecord { return []DNSRecord{} }
func getAdditionalRecords(q DNSQuestion) []DNSRecord  { return []DNSRecord{} }
