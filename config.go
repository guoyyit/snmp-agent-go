package main

import (
	"encoding/json"
	"os"
)

// config holds agent configuration.
type config struct {
	ListenAddr        string   `json:"listenAddr"`
	ROCommunity       string   `json:"roCommunity"`
	RWCommunity       string   `json:"rwCommunity"`
	StatePath         string   `json:"statePath"`
	TrapTargets       []string `json:"trapTargets"`
	TrapCommunity     string   `json:"trapCommunity"`
	InformRetries     int      `json:"informRetries"`
	InformTimeoutMS   int      `json:"informTimeoutMs"`
	ResponseSizeLimit int      `json:"responseSizeLimit"`
}

func defaultConfig() *config {
	return &config{
		ListenAddr:        "127.0.0.1:1161",
		ROCommunity:       "public",
		RWCommunity:       "private",
		StatePath:         "agent-state.json",
		TrapCommunity:     "public",
		InformRetries:     3,
		InformTimeoutMS:   1000,
		ResponseSizeLimit: 1400,
	}
}

// loadConfig reads a JSON config file, falling back to defaults for
// missing fields.
func loadConfig(path string) (*config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// accessLevelFor returns the access level granted by a community string.
func (c *config) accessLevelFor(community string) accessLevel {
	switch community {
	case c.RWCommunity:
		return accessReadWrite
	case c.ROCommunity:
		return accessReadOnly
	}
	return accessNone
}

type accessLevel int

const (
	accessNone accessLevel = iota
	accessReadOnly
	accessReadWrite
)
