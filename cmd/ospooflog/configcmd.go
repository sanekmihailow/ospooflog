package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"
)

// runConfig dispatches the `config` subcommands. active is the config command;
// active.Active is the chosen show / edit / path. cfg is the merged config.
func runConfig(active *flags.Command, cfg config) error {
	if active.Active == nil {
		return errors.New("config: specify a subcommand: show | edit | path")
	}
	switch active.Active.Name {
	case "show":
		return configShow(os.Stdout, cfg)
	case "path":
		return configPath(os.Stdout)
	case "edit":
		return configEdit()
	default:
		return fmt.Errorf("unknown config subcommand: %s", active.Active.Name)
	}
}

// configShow prints the effective merged config as YAML — only the keys that
// are actually set (the struct tags are omitempty).
func configShow(w io.Writer, cfg config) error {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) == "{}" {
		_, err := fmt.Fprintln(w, "# no config set (all built-in defaults)")
		return err
	}
	_, err = fmt.Fprint(w, string(out))
	return err
}

// configPath lists each config location in priority order and whether it loads.
func configPath(w io.Writer) error {
	for _, p := range configPaths() {
		status := "not found"
		if _, err := os.Stat(p); err == nil {
			status = "loaded"
		}
		if _, err := fmt.Fprintf(w, "%s (%s)\n", p, status); err != nil {
			return err
		}
	}
	return nil
}

// configEdit opens a config file in $EDITOR (vi fallback): the highest-priority
// existing file, or a freshly bootstrapped per-user config if none exists yet.
func configEdit() error {
	paths := configPaths() // [user, project] — project overrides, so edit it last-wins
	target := ""
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			target = p
		}
	}
	if target == "" {
		target = paths[0] // bootstrap the per-user config
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte("# ospooflog config — keys: mode, session, ignore, overrides, cut, keep_tld, json, fast_restore, allow_keys, debug, debug_out\n"), 0o600); err != nil {
			return err
		}
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	fmt.Fprintf(os.Stderr, "editing %s with %s\n", target, editor)
	c := exec.Command(editor, target)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
