package provider

import (
	stdcontext "context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type Resolver interface {
	LookupIP(context stdcontext.Context, network string, host string) ([]net.IP, error)
}

type EndpointSet struct {
	endpoints map[Endpoint]struct{}
	prefixes  []netip.Prefix
}

func ResolveConfig(ctx stdcontext.Context, resolver Resolver, cfg Config) (EndpointSet, error) {
	if len(cfg.Targets) == 0 && len(cfg.CIDRs) == 0 {
		return EndpointSet{}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	out := EndpointSet{
		endpoints: make(map[Endpoint]struct{}),
		prefixes:  append([]netip.Prefix(nil), cfg.CIDRs...),
	}

	for _, target := range cfg.Targets {
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

func StartBackgroundRefresh(
	ctx stdcontext.Context,
	resolver Resolver,
	cfg Config,
	interval time.Duration,
	classifier *Classifier,
) {
	if classifier == nil || interval <= 0 {
		return
	}
	if len(cfg.Targets) == 0 && len(cfg.CIDRs) == 0 {
		return
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				endpoints, err := ResolveConfig(ctx, resolver, cfg)
				if err != nil {
					log.Printf("configured connect refresh failed: %v", err)
					continue
				}
				classifier.ReplaceEndpoints(endpoints)
				log.Printf("configured connect endpoints refreshed")
			}
		}
	}()
}
