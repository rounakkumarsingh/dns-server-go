package dns

import "fmt"

type Record uint16

var RecordType = struct {
	A     Record
	NS    Record
	MD    Record
	MF    Record
	CNAME Record
	SOA   Record
	MB    Record
	MG    Record
	MR    Record
	NULL  Record
	WKS   Record
	PTR   Record
	HINFO Record
	MINFO Record
	MX    Record
	TXT   Record
	AAAA  Record
	SRV   Record
	OPT   Record
	CAA   Record
	ANY   Record
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

var RecordName = map[Record]string{
	RecordType.A:     "A",
	RecordType.NS:    "NS",
	RecordType.MD:    "MD",
	RecordType.MF:    "MF",
	RecordType.CNAME: "CNAME",
	RecordType.SOA:   "SOA",
	RecordType.MB:    "MB",
	RecordType.MG:    "MG",
	RecordType.MR:    "MR",
	RecordType.NULL:  "NULL",
	RecordType.WKS:   "WKS",
	RecordType.PTR:   "PTR",
	RecordType.HINFO: "HINFO",
	RecordType.MINFO: "MINFO",
	RecordType.MX:    "MX",
	RecordType.TXT:   "TXT",
	RecordType.AAAA:  "AAAA",
	RecordType.SRV:   "SRV",
	RecordType.OPT:   "OPT",
	RecordType.CAA:   "CAA",
	RecordType.ANY:   "ANY",
}

func (r Record) String() string {
	val, ok := RecordName[r]
	if ok {
		return val
	}
	return fmt.Sprintf("%d", r)
}
