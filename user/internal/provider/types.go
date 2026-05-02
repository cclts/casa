package provider

import "net/netip"

type Target struct {
	Host string
	Port uint16
}

type Config struct {
	Targets []Target
	CIDRs   []netip.Prefix
}

type Endpoint struct {
	Addr netip.Addr
	Port uint16
}
