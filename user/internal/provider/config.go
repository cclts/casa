package provider

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cclts/casa/user/internal/rules"
)

func TargetsFromAnalysis(analysis rules.AnalysisConfig) ([]Target, error) {
	rawTargets := append([]string(nil), analysis.LLMProviderURLs...)
	rawTargets = append(rawTargets, analysis.ChannelURLs...)
	if len(rawTargets) == 0 {
		return nil, nil
	}

	targets := make([]Target, 0, len(rawTargets))
	for _, raw := range rawTargets {
		target, err := parseTarget(raw)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
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
