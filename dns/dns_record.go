package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type DNSRecordPreamble struct {
	Name  string
	Type  Record
	Class Class
	TTL   uint32
}

func (a DNSRecordPreamble) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf := encodeDomainName(a.Name, offsetMap, offSet)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	ttlBytes := make([]byte, 4)

	binary.BigEndian.PutUint16(typeBytes, uint16(a.Type))
	binary.BigEndian.PutUint16(classBytes, uint16(a.Class))
	binary.BigEndian.PutUint32(ttlBytes, a.TTL)

	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)
	buf = append(buf, ttlBytes...)

	return buf, nil

}

func (a DNSRecordPreamble) String() string {
	return "DNS Record:\n" +
		"  Name: " + a.Name + "\n" +
		"  Type: " + a.Type.String() + "\n" +
		"  Class: " + a.Class.String() + "\n" +
		"  TTL: " + fmt.Sprint(a.TTL)
}

type DNSRecord interface {
	preamble() DNSRecordPreamble
	ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error)
	String() string
}

// ARecord represents a DNS record of type A (Address).

type ADNSRecord struct {
	DNSRecordPreamble
	IP net.IP
}

func (r ADNSRecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r ADNSRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	if r.IP.To4() == nil {
		return nil, errors.New("IP address is not an IPv4 address")
	}
	rData := []byte(r.IP.To4())

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r ADNSRecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  IP: " + r.IP.String()
}

// NSDNSRecord represents a DNS record of type NS (Name Server).

type NSDNSRecord struct {
	DNSRecordPreamble
	Host string
}

func (r NSDNSRecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r NSDNSRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	rData := encodeDomainName(r.Host, offsetMap, offSet+uint(len(buf)))

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r NSDNSRecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  Host: " + r.Host
}

// CNAMERecord represents a DNS record of type CNAME (Canonical Name).
type CNAMERecord struct {
	DNSRecordPreamble
	CanonicalName string
}

func (r CNAMERecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r CNAMERecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	rData := encodeDomainName(r.CanonicalName, offsetMap, offSet+uint(len(buf)))

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r CNAMERecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  Canonical Name: " + r.CanonicalName
}

// TXTRecord represents a DNS record of type TXT (Text).
type TXTRecord struct {
	DNSRecordPreamble
	Text string
}

func (r TXTRecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r TXTRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	rData := []byte(r.Text)

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r TXTRecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  Text: " + r.Text
}

// MX Record represents a DNS record of type MX (Mail Exchange).
type MXRecord struct {
	DNSRecordPreamble
	Preference uint16
	Exchange   string
}

func (r MXRecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r MXRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	preferenceBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(preferenceBytes, r.Preference)

	rData := encodeDomainName(r.Exchange, offsetMap, offSet+uint(len(buf)+len(preferenceBytes)))

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(preferenceBytes)+len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, preferenceBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r MXRecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  Preference: " + fmt.Sprint(r.Preference) + "\n" +
		"  Exchange: " + r.Exchange
}

// AAAARecord represents a DNS record of type AAAA (IPv6 Address).
type AAAARecord struct {
	DNSRecordPreamble
	IP net.IP
}

func (r AAAARecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r AAAARecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	if r.IP.To16() == nil {
		return nil, errors.New("IP address is not an IPv6 address")
	}
	rData := []byte(r.IP.To16())

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

// SOARecord represents a DNS record of type SOA (Start of Authority).
type SOARecord struct {
	DNSRecordPreamble
	MName      string // Primary name server
	RName      string // Responsible person
	Serial     uint32 // Serial number
	Refresh    uint32 // Refresh interval
	Retry      uint32 // Retry interval
	Expire     uint32 // Expiration limit
	MinimumTTL uint32 // Minimum TTL
}

func (r SOARecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r SOARecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	mNameData := encodeDomainName(r.MName, offsetMap, offSet+uint(len(buf)))
	rNameData := encodeDomainName(r.RName, offsetMap, offSet+uint(len(buf)+len(mNameData)))

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(mNameData)+len(rNameData)+20))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, mNameData...)
	buf = append(buf, rNameData...)

	// Append the numeric fields
	binary.BigEndian.PutUint32(buf, r.Serial)
	binary.BigEndian.PutUint32(buf[4:], r.Refresh)
	binary.BigEndian.PutUint32(buf[8:], r.Retry)
	binary.BigEndian.PutUint32(buf[12:], r.Expire)
	binary.BigEndian.PutUint32(buf[16:], r.MinimumTTL)

	return buf, nil
}

func (r SOARecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  MName: " + r.MName + "\n" +
		"  RName: " + r.RName + "\n" +
		"  Serial: " + fmt.Sprint(r.Serial) + "\n" +
		"  Refresh: " + fmt.Sprint(r.Refresh) + "\n" +
		"  Retry: " + fmt.Sprint(r.Retry) + "\n" +
		"  Expire: " + fmt.Sprint(r.Expire) + "\n" +
		"  Minimum TTL: " + fmt.Sprint(r.MinimumTTL)
}

// PTRRecord represents a DNS record of type PTR (Pointer).
type PTRRecord struct {
	DNSRecordPreamble
	Pointer string // Domain name to which the PTR record points
}

func (r PTRRecord) preamble() DNSRecordPreamble {
	return r.DNSRecordPreamble
}

func (r PTRRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.DNSRecordPreamble.ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	rData := encodeDomainName(r.Pointer, offsetMap, offSet+uint(len(buf)))

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rData)))

	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rData...)

	return buf, nil
}

func (r PTRRecord) String() string {
	return r.DNSRecordPreamble.String() + "\n" +
		"  Pointer: " + r.Pointer
}

// SPFRecord represents a DNS record of type SPF (Sender Policy Framework).
type SPFRecord struct {
	TXTRecord
}

// OPTRecord represents a DNS record of type OPT (EDNS0).
type EDNSOption struct {
	Code uint16
	Data []byte
}

type OPTRecord struct {
	Name     string       // Name is always empty for OPT records
	UDPSize  uint16       // UDPSize is the maximum size of the UDP payload
	ExtRCODE uint8        // Extended response code
	Version  uint8        // Version of the EDNS0 protocol
	DO       bool         // DNSSEC OK flag
	Z        uint16       // Other flags, reserved for future use
	Options  []EDNSOption // Options field, contains EDNS options
}

func (r OPTRecord) preamble() DNSRecordPreamble {
	serializedZ := r.Z
	if r.DO {
		serializedZ |= 0x8000
	}
	ttl := (uint32(r.ExtRCODE) << 24) | (uint32(r.Version) << 16) | uint32(serializedZ)
	return DNSRecordPreamble{
		Name:  r.Name,
		Type:  RecordType.OPT,
		Class: Class(r.UDPSize),
		TTL:   ttl,
	}
}

func (r OPTRecord) ToBytes(offsetMap map[string]uint, offSet uint) ([]byte, error) {
	buf, err := r.preamble().ToBytes(offsetMap, offSet)
	if err != nil {
		return nil, err
	}

	rdata := make([]byte, 0)
	for _, option := range r.Options {
		optionData := make([]byte, 4+len(option.Data))
		binary.BigEndian.PutUint16(optionData[:2], option.Code)
		binary.BigEndian.PutUint16(optionData[2:4], uint16(len(option.Data)))
		copy(optionData[4:], option.Data)
		rdata = append(rdata, optionData...)
	}
	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(rdata)))
	buf = append(buf, rdLengthBytes...)
	buf = append(buf, rdata...)

	return buf, nil
}

func (r OPTRecord) String() string {
	str := "OPT Record:\n"
	str += fmt.Sprintf("  UDPSize: %d\n", r.UDPSize)
	str += fmt.Sprintf("  ExtRCODE: %d\n", r.ExtRCODE)
	str += fmt.Sprintf("  Version: %d\n", r.Version)
	str += fmt.Sprintf("  DO: %v\n", r.DO)
	str += fmt.Sprintf("  Z: %d\n", r.Z)
	if len(r.Options) > 0 {
		str += "  Options:\n"
		for _, opt := range r.Options {
			str += fmt.Sprintf("    Code: %d, Data: %x\n", opt.Code, opt.Data)
		}
	} else {
		str += "  Options: none\n"
	}
	return str
}
