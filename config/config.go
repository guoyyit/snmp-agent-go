package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

var ErrNotFound = errors.New("config: file not found")

// PersistedValue is the on-disk representation of an object value.
type PersistedValue struct {
	Syntax string
	Raw    string
}

// NewPersistedValue hex-encodes a raw value for persistence.
func NewPersistedValue(syntax string, raw []byte) PersistedValue {
	return PersistedValue{Syntax: syntax, Raw: hex.EncodeToString(raw)}
}

// DecodeRaw returns the decoded raw bytes.
func (p PersistedValue) DecodeRaw() ([]byte, error) {
	return hex.DecodeString(p.Raw)
}

// Config is the persisted agent configuration.
type Config struct {
	ListenAddr         string
	ReadOnlyCommunity  string
	ReadWriteCommunity string
	Values             map[string]PersistedValue
}

func Default() *Config {
	return &Config{
		ListenAddr:         "127.0.0.1:1610",
		ReadOnlyCommunity:  "public",
		ReadWriteCommunity: "private",
		Values:             make(map[string]PersistedValue),
	}
}

// Load reads and validates the persisted configuration. Missing files yield
// the default configuration rather than an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return nil, err
	}
	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate enforces non-empty communities and distinct privilege levels.
func (c *Config) Validate() error {
	if c.ListenAddr == "" || c.ReadOnlyCommunity == "" || c.ReadWriteCommunity == "" {
		return errors.New("config: empty required field")
	}
	if c.ReadOnlyCommunity == c.ReadWriteCommunity {
		return errors.New("config: read-only and read-write communities must differ")
	}
	return nil
}

// Save atomically replaces the configuration file: a crash during save can
// leave either the old file or the new one, never a torn middle state.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".snmp-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
