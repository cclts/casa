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
	if addr == "" || e.Port == 0 || len(s.endpoints) == 0 {
		return false
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}

	_, ok := s.endpoints[Endpoint{
		Addr: parsed.Unmap(),
		Port: e.Port,
	}]
	return ok
}
