package provider

import (
	"net/netip"
	"strings"

	"github.com/cclts/casa/user/internal/event"
)

func (s EndpointSet) ContainsConnect(e event.Event) bool {
	if e.Type != event.EventConnect {
		return false
	}

	addr := strings.TrimSpace(e.Addr)
	if addr == "" || e.Port == 0 {
		return false
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	parsed = parsed.Unmap()

	for _, prefix := range s.prefixes {
		if prefix.Contains(parsed) {
			return true
		}
	}

	if len(s.endpoints) == 0 {
		return false
	}

	_, ok := s.endpoints[Endpoint{
		Addr: parsed,
		Port: e.Port,
	}]
	return ok
}
