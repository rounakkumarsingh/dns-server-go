package main

import "github.com/rounakkumarsingh/dns-server/dns"

type RESCODEError struct {
	Code dns.DNSResponseCode
}

func (r RESCODEError) Error() string {
	return "DNS Response Code: " + r.Code.String()
}
