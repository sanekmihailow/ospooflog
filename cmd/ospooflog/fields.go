package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/jsonproc"
	"gopkg.in/yaml.v3"
)

type fieldsFile struct {
	Fields map[string]string `yaml:"fields"`
}

// loadFieldRules reads a --fields YAML file (dotted-path → action) into the
// jsonproc rule set. Used only in --json mode.
func loadFieldRules(path string) (jsonproc.FieldRules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f fieldsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	rules := make(jsonproc.FieldRules, len(f.Fields))
	for field, action := range f.Fields {
		rule, err := parseFieldAction(action)
		if err != nil {
			return nil, ruleErr(fmt.Errorf("%s: field %q: %w", path, field, err))
		}
		rules[field] = rule
	}
	return rules, nil
}

// parseFieldAction maps an action token to a rule: keep | mask | remove |
// mask-as:KIND (KIND is a detector kind, case-insensitive, validated against
// the same set --mask accepts).
func parseFieldAction(s string) (jsonproc.FieldRule, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "keep":
		return jsonproc.FieldRule{Action: jsonproc.ActionKeep}, nil
	case "mask":
		return jsonproc.FieldRule{Action: jsonproc.ActionMask}, nil
	case "remove":
		return jsonproc.FieldRule{Action: jsonproc.ActionRemove}, nil
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(s)), "mask-as:"); ok {
		k, ok := knownKind(rest)
		if !ok {
			return jsonproc.FieldRule{}, fmt.Errorf("unknown kind %q in mask-as (see `--help --mask` for kinds)", rest)
		}
		return jsonproc.FieldRule{Action: jsonproc.ActionMaskAs, Kind: k}, nil
	}
	return jsonproc.FieldRule{}, fmt.Errorf("unknown action %q (want keep|mask|remove|mask-as:KIND)", s)
}
