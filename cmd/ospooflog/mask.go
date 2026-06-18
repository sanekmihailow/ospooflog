package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

// maskGroups names the kind categories selectable via --mask. A group is just a
// convenience alias for its kinds; --mask also accepts bare kind names.
var maskGroups = map[string][]detector.EntityKind{
	"secrets": {detector.KindPassword, detector.KindAPIKey, detector.KindToken, detector.KindDSN, detector.KindPrivKey},
	"pii":     {detector.KindEmail, detector.KindUser, detector.KindPhone, detector.KindCard, detector.KindIP, detector.KindIP6, detector.KindMAC, detector.KindAddr, detector.KindSID},
	"infra":   {detector.KindHost, detector.KindFQDN, detector.KindPort, detector.KindPath, detector.KindARN},
	"ids":     {detector.KindUUID, detector.KindPubKey, detector.KindFingerprint},
}

// parseMask turns a --mask spec ("secrets,pii", "secrets,EMAIL", "all") into the
// set of kinds to emit. A nil result means "emit everything" (the default and
// the explicit "all"), so the detector skips the filter entirely.
func parseMask(spec string) (map[detector.EntityKind]bool, error) {
	allowed := map[detector.EntityKind]bool{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.EqualFold(tok, "all") {
			return nil, nil
		}
		if kinds, ok := maskGroups[strings.ToLower(tok)]; ok {
			for _, k := range kinds {
				allowed[k] = true
			}
			continue
		}
		if k, ok := knownKind(tok); ok {
			allowed[k] = true
			continue
		}
		return nil, fmt.Errorf("--mask: unknown group or kind %q (groups: %s)", tok, strings.Join(maskGroupNames(), ", "))
	}
	if len(allowed) == 0 {
		return nil, nil
	}
	return allowed, nil
}

// knownKind resolves a bare kind name (case-insensitive) to its EntityKind,
// drawing the valid set from the group membership so the two never drift.
func knownKind(tok string) (detector.EntityKind, bool) {
	up := detector.EntityKind(strings.ToUpper(strings.TrimSpace(tok)))
	for _, kinds := range maskGroups {
		for _, k := range kinds {
			if k == up {
				return k, true
			}
		}
	}
	return "", false
}

func maskGroupNames() []string {
	names := make([]string, 0, len(maskGroups))
	for n := range maskGroups {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
