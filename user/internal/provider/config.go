package provider

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cclts/casa/user/internal/rules"
)

func TargetsFromAnalysis(analysis rules.AnalysisConfig) ([]Target, error) {
	if len(analysis.LLMProviderURLs) == 0 {
		return nil, nil
	}

	targets := make([]Target, 0, len(analysis.LLMProviderURLs))
	for _, raw := range analysis.LLMProviderURLs {
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
		return Target{}, fmt.Errorf("llm_provider_urls contains empty value")
	}

	u, err := url.Parse(value)
	if err != nil {
		return Target{}, fmt.Errorf("parse llm provider url %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("llm provider url %q missing host", raw)
	}

	port := uint16(443)
	if u.Port() != "" {
		p, err := parsePort(u.Port())
		if err != nil {
			return Target{}, fmt.Errorf("parse llm provider url %q port: %w", raw, err)
		}
		port = p
	}

	return Target{
		Host: strings.ToLower(strings.TrimSpace(u.Hostname())),
		Port: port,
	}, nil
}
