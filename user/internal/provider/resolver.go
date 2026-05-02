package provider

import (
	stdcontext "context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

type Resolver interface {
	LookupIP(context stdcontext.Context, network string, host string) ([]net.IP, error)
}

type EndpointSet struct {
	endpoints map[Endpoint]struct{}
}

func ResolveTargets(ctx stdcontext.Context, resolver Resolver, targets []Target) (EndpointSet, error) {
	if len(targets) == 0 {
		return EndpointSet{}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	out := EndpointSet{
		endpoints: make(map[Endpoint]struct{}),
	}

	for _, target := range targets {
		ips, err := resolver.LookupIP(ctx, "ip", target.Host)
		if err != nil {
			return EndpointSet{}, fmt.Errorf("resolve %s: %w", target.Host, err)
		}
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			out.endpoints[Endpoint{
				Addr: addr.Unmap(),
				Port: target.Port,
			}] = struct{}{}
		}
	}

	return out, nil
}

func parsePort(raw string) (uint16, error) {
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(value), nil
}
