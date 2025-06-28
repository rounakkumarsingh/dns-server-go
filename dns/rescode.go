package dns

type DNSResponseCode uint8

var DNSResponseCodeType = struct {
	NoError        DNSResponseCode
	FormatError    DNSResponseCode
	ServerFailure  DNSResponseCode
	NameError      DNSResponseCode
	NotImplemented DNSResponseCode
	Refused        DNSResponseCode
	BadSignature   DNSResponseCode
	BadKey         DNSResponseCode
	BadTime        DNSResponseCode
}{
	NoError:        0,
	FormatError:    1,
	ServerFailure:  2,
	NameError:      3,
	NotImplemented: 4,
	Refused:        5,
	BadSignature:   6,
	BadKey:         7,
	BadTime:        8,
}

func (r DNSResponseCode) String() string {
	switch r {
	case DNSResponseCodeType.NoError:
		return "NoError"
	case DNSResponseCodeType.FormatError:
		return "FormatError"
	case DNSResponseCodeType.ServerFailure:
		return "ServerFailure"
	case DNSResponseCodeType.NameError:
		return "NameError"
	case DNSResponseCodeType.NotImplemented:
		return "NotImplemented"
	case DNSResponseCodeType.Refused:
		return "Refused"
	case DNSResponseCodeType.BadSignature:
		return "BadSignature"
	case DNSResponseCodeType.BadKey:
		return "BadKey"
	case DNSResponseCodeType.BadTime:
		return "BadTime"
	default:
		return "Unknown Response Code"
	}
}
