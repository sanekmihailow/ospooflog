package main

import (
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestParseMask(t *testing.T) {
	cases := []struct {
		spec string
		want map[detector.EntityKind]bool
		err  bool
	}{
		{"", nil, false},            // empty → no filter (all)
		{"all", nil, false},         // explicit all → no filter
		{"secrets,all", nil, false}, // all anywhere wins
		{"secrets", map[detector.EntityKind]bool{
			detector.KindPassword: true, detector.KindAPIKey: true,
			detector.KindToken: true, detector.KindDSN: true, detector.KindPrivKey: true,
		}, false},
		{"PII", map[detector.EntityKind]bool{ // group name is case-insensitive
			detector.KindEmail: true, detector.KindUser: true, detector.KindPhone: true,
			detector.KindCard: true, detector.KindIP: true, detector.KindIP6: true,
			detector.KindMAC: true, detector.KindAddr: true, detector.KindSID: true,
		}, false},
		{"secrets , email", map[detector.EntityKind]bool{ // group + bare kind, spaces trimmed
			detector.KindPassword: true, detector.KindAPIKey: true, detector.KindToken: true,
			detector.KindDSN: true, detector.KindPrivKey: true, detector.KindEmail: true,
		}, false},
		{"bogus", nil, true}, // unknown group/kind → error
	}
	for _, c := range cases {
		got, err := parseMask(c.spec)
		if (err != nil) != c.err {
			t.Errorf("parseMask(%q) err = %v, want err=%v", c.spec, err, c.err)
			continue
		}
		if c.err {
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseMask(%q) = %v, want %v", c.spec, got, c.want)
			continue
		}
		for k := range c.want {
			if !got[k] {
				t.Errorf("parseMask(%q) missing %s", c.spec, k)
			}
		}
	}
}
