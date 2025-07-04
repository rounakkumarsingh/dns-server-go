package dns

import "fmt"

type RecordType uint16

var RType = struct {
	A     RecordType
	NS    RecordType
	MD    RecordType
	MF    RecordType
	CNAME RecordType
	SOA   RecordType
	MB    RecordType
	MG    RecordType
	MR    RecordType
	NULL  RecordType
	WKS   RecordType
	PTR   RecordType
	HINFO RecordType
	MINFO RecordType
	MX    RecordType
	TXT   RecordType
	AAAA  RecordType
	SRV   RecordType
	OPT   RecordType
	CAA   RecordType
	ANY   RecordType
}{
	A:     1,
	NS:    2,
	MD:    3,
	MF:    4,
	CNAME: 5,
	SOA:   6,
	MB:    7,
	MG:    8,
	MR:    9,
	NULL:  10,
	WKS:   11,
	PTR:   12,
	HINFO: 13,
	MINFO: 14,
	MX:    15,
	TXT:   16,
	AAAA:  28,
	SRV:   33,
	OPT:   41,
	CAA:   257,
	ANY:   255,
}

var RecordName = map[RecordType]string{
	RType.A:     "A",
	RType.NS:    "NS",
	RType.MD:    "MD",
	RType.MF:    "MF",
	RType.CNAME: "CNAME",
	RType.SOA:   "SOA",
	RType.MB:    "MB",
	RType.MG:    "MG",
	RType.MR:    "MR",
	RType.NULL:  "NULL",
	RType.WKS:   "WKS",
	RType.PTR:   "PTR",
	RType.HINFO: "HINFO",
	RType.MINFO: "MINFO",
	RType.MX:    "MX",
	RType.TXT:   "TXT",
	RType.AAAA:  "AAAA",
	RType.SRV:   "SRV",
	RType.OPT:   "OPT",
	RType.CAA:   "CAA",
	RType.ANY:   "ANY",
}

func (r RecordType) String() string {
	val, ok := RecordName[r]
	if ok {
		return val
	}
	return fmt.Sprintf("%d", r)
}
