package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// config mirrors the subset of flags that may be set in a YAML file, so the
// same options don't have to be repeated on every invocation. Bool fields are
// pointers to tell "absent" from an explicit false during the merge. proxy
// settings and named profiles are intentionally absent — no such feature
// exists yet, so there'd be nothing to configure.
type config struct {
	Mode        string `yaml:"mode,omitempty"`
	Session     string `yaml:"session,omitempty"`
	AllowKeys   string `yaml:"allow_keys,omitempty"`
	Ignore      string `yaml:"ignore,omitempty"`
	Overrides   string `yaml:"overrides,omitempty"`
	Cut         string `yaml:"cut,omitempty"`
	DebugOut    string `yaml:"debug_out,omitempty"`
	FastRestore *bool  `yaml:"fast_restore,omitempty"`
	JSON        *bool  `yaml:"json,omitempty"`
	KeepTLD     *bool  `yaml:"keep_tld,omitempty"`
	Debug       *int   `yaml:"debug,omitempty"`
}

// configPaths lists config locations in increasing priority: the per-user file
// first, the project file (current directory) last.
func configPaths() []string {
	var paths []string
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "ospooflog", "config.yaml"))
	}
	return append(paths, ".ospooflog.yaml")
}

func loadConfig() (config, error) { return loadConfigFrom(configPaths()) }

// loadConfigFrom reads each path in order and overlays it onto the accumulator,
// so a later (higher-priority) file overrides an earlier one per key. A missing
// file is skipped; a malformed one is an error.
func loadConfigFrom(paths []string) (config, error) {
	var cfg config
	for _, p := range paths {
		c, ok, err := readConfig(p)
		if err != nil {
			return cfg, err
		}
		if ok {
			cfg.overlay(c)
			dbg.at(1, "config: loaded %s", p)
		}
	}
	return cfg, nil
}

func readConfig(path string) (config, bool, error) {
	var c config
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, false, nil
		}
		return c, false, err
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, false, fmt.Errorf("config %s: %w", path, err)
	}
	return c, true, nil
}

// overlay copies the set fields of o (the higher-priority source) over c.
func (c *config) overlay(o config) {
	if o.Mode != "" {
		c.Mode = o.Mode
	}
	if o.Session != "" {
		c.Session = o.Session
	}
	if o.AllowKeys != "" {
		c.AllowKeys = o.AllowKeys
	}
	if o.Ignore != "" {
		c.Ignore = o.Ignore
	}
	if o.Overrides != "" {
		c.Overrides = o.Overrides
	}
	if o.Cut != "" {
		c.Cut = o.Cut
	}
	if o.DebugOut != "" {
		c.DebugOut = o.DebugOut
	}
	if o.FastRestore != nil {
		c.FastRestore = o.FastRestore
	}
	if o.JSON != nil {
		c.JSON = o.JSON
	}
	if o.KeepTLD != nil {
		c.KeepTLD = o.KeepTLD
	}
	if o.Debug != nil {
		c.Debug = o.Debug
	}
}

// applyTo fills opts fields the CLI flags left unset (empty string, or false for
// an opt-in bool) from the config, so the effective precedence is
// flag > config > built-in default.
func (c config) applyTo(o *opts) {
	if o.Mode == "" {
		o.Mode = c.Mode
	}
	if o.Session == "" {
		o.Session = c.Session
	}
	if o.AllowKeys == "" {
		o.AllowKeys = c.AllowKeys
	}
	if o.Ignore == "" {
		o.Ignore = c.Ignore
	}
	if o.Overrides == "" {
		o.Overrides = c.Overrides
	}
	if o.Cut == "" {
		o.Cut = c.Cut
	}
	if o.DebugOut == "" {
		o.DebugOut = c.DebugOut
	}
	if !o.FastRestore && c.FastRestore != nil {
		o.FastRestore = *c.FastRestore
	}
	if !o.JSON && c.JSON != nil {
		o.JSON = *c.JSON
	}
	if !o.KeepTLD && c.KeepTLD != nil {
		o.KeepTLD = *c.KeepTLD
	}
	if o.Debug == 0 && c.Debug != nil {
		o.Debug = *c.Debug
	}
}
