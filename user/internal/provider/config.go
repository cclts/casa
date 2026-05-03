package provider

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/cclts/casa/user/internal/rules"
)

func ConfigFromAnalysis(analysis rules.AnalysisConfig) (Config, error) {
	rawTargets := append([]string(nil), analysis.LLMProviderURLs...)
	rawTargets = append(rawTargets, analysis.ChannelURLs...)
	targets := make([]Target, 0, len(rawTargets))
	for _, raw := range rawTargets {
		target, err := parseTarget(raw)
		if err != nil {
			return Config{}, err
		}
		targets = append(targets, target)
	}

	prefixes := make([]netip.Prefix, 0, len(analysis.KnownCIDRs))
	for _, raw := range analysis.KnownCIDRs {
		prefix, err := parseCIDR(raw)
		if err != nil {
			return Config{}, err
		}
		prefixes = append(prefixes, prefix)
	}

	return Config{
		Targets: targets,
		CIDRs:   prefixes,
	}, nil
}

func parseTarget(raw string) (Target, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Target{}, fmt.Errorf("configured urls contain empty value")
	}

	u, err := url.Parse(value)
	if err != nil {
		return Target{}, fmt.Errorf("parse configured url %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("configured url %q missing host", raw)
	}

	port := uint16(443)
	if u.Port() != "" {
		p, err := parsePort(u.Port())
		if err != nil {
			return Target{}, fmt.Errorf("parse configured url %q port: %w", raw, err)
		}
		port = p
	}

	return Target{
		Host: strings.ToLower(strings.TrimSpace(u.Hostname())),
		Port: port,
	}, nil
}

func parseCIDR(raw string) (netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("known_cidrs contains empty value")
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse known cidr %q: %w", raw, err)
	}
	return prefix.Masked(), nil
}
