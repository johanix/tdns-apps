package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ZoneConfig struct {
	Name   string `yaml:"name"`   // e.g. "se."
	Source string `yaml:"source"` // e.g. "dns.iis.se:53"
}

type WhoisConfig struct {
	Server      string `yaml:"server"`      // e.g. "whois.iis.se:43"
	RateLimit   int    `yaml:"rate_limit"`  // queries per second (token bucket rate)
	Burst       int    `yaml:"burst"`       // bucket burst capacity
	Concurrency int    `yaml:"concurrency"` // worker goroutines
	TimeoutSec  int    `yaml:"timeout_sec"` // per-query timeout
}

type DBConfig struct {
	Path string `yaml:"path"` // filesystem path to sqlite file
}

type ReportConfig struct {
	// Domain is considered matched if ANY of these EPP status codes
	// is present in the whois response.
	MatchStatuses []string `yaml:"match_statuses"`
}

type Config struct {
	Zone   ZoneConfig   `yaml:"zone"`
	Whois  WhoisConfig  `yaml:"whois"`
	DB     DBConfig     `yaml:"db"`
	Report ReportConfig `yaml:"report"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{
		Whois: WhoisConfig{
			Server:      "whois.iis.se:43",
			RateLimit:   2,
			Burst:       4,
			Concurrency: 3,
			TimeoutSec:  10,
		},
		DB: DBConfig{
			Path: "./sewhois.sqlite",
		},
		Report: ReportConfig{
			MatchStatuses: []string{
				"serverTransferProhibited",
				"serverRenewProhibited",
			},
		},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Zone.Name == "" {
		return nil, fmt.Errorf("zone.name is required")
	}
	if cfg.Zone.Source == "" {
		return nil, fmt.Errorf("zone.source is required (server to AXFR from, host:port)")
	}
	if cfg.Whois.RateLimit <= 0 {
		return nil, fmt.Errorf("whois.rate_limit must be > 0")
	}
	if cfg.Whois.Concurrency <= 0 {
		return nil, fmt.Errorf("whois.concurrency must be > 0")
	}
	if len(cfg.Report.MatchStatuses) == 0 {
		return nil, fmt.Errorf("report.match_statuses must list at least one EPP status code")
	}
	return cfg, nil
}
