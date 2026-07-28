// Package config loads sekisho.yaml. M1a implements only the listeners
// section (LLD §11); stores, sinks, and the rest arrive with the
// milestones that need them.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Listener is one reception endpoint.
type Listener struct {
	Kind string `yaml:"kind"`
	Bind string `yaml:"bind"`
}

// Config is the recognized subset of sekisho.yaml.
type Config struct {
	Listeners []Listener `yaml:"listeners"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if len(c.Listeners) == 0 {
		return nil, fmt.Errorf("config: %q defines no listeners", path)
	}
	for i, l := range c.Listeners {
		if l.Kind != "udp" {
			return nil, fmt.Errorf("config: listeners[%d]: unsupported kind %q (only udp)", i, l.Kind)
		}
		if l.Bind == "" {
			return nil, fmt.Errorf("config: listeners[%d]: bind is required", i)
		}
	}
	return &c, nil
}
