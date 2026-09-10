//go:build linux || darwin

// Package privatepki initializes the isolated backend identities of a reference installation.
package privatepki

import (
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrConfiguration = errors.New("private PKI configuration is invalid")
	ErrState         = errors.New("private PKI state is incomplete, changed or belongs to another installation")
	ErrLocked        = errors.New("another initializer owns the private PKI directory")
	ErrCertificate   = errors.New("private PKI identity is invalid or expired; restore or explicitly rotate it")
)

type Config struct {
	Version       int      `json:"version"`
	Name          string   `json:"name"`
	ConsoleNames  []string `json:"console_names"`
	BrokerNames   []string `json:"broker_names"`
	DatabaseNames []string `json:"database_names,omitempty"`
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (c Config) normalized() (Config, error) {
	if c.Version != 1 || !label.MatchString(c.Name) {
		return Config{}, ErrConfiguration
	}
	c.ConsoleNames = slices.Clone(c.ConsoleNames)
	c.BrokerNames = slices.Clone(c.BrokerNames)
	c.DatabaseNames = slices.Clone(c.DatabaseNames)
	groups := [][]string{c.ConsoleNames, c.BrokerNames}
	if len(c.DatabaseNames) != 0 {
		groups = append(groups, c.DatabaseNames)
	}
	seen := map[string]bool{}
	for _, names := range groups {
		if len(names) < 1 || len(names) > 8 {
			return Config{}, ErrConfiguration
		}
		for _, name := range names {
			if seen[name] || len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
				return Config{}, ErrConfiguration
			}
			seen[name] = true
			for _, part := range strings.Split(name, ".") {
				if !label.MatchString(part) {
					return Config{}, ErrConfiguration
				}
			}
		}
		slices.Sort(names)
		for i := 1; i < len(names); i++ {
			if names[i] == names[i-1] {
				return Config{}, ErrConfiguration
			}
		}
	}
	return c, nil
}

func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsRune(path, 0)
}
