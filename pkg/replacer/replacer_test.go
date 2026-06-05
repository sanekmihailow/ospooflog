package replacer

import (
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestGenerate_Basic(t *testing.T) {
	r := New()
	cases := []struct {
		kind  detector.EntityKind
		n     int
		extra map[string]string
		want  string
	}{
		{detector.KindIP, 1, nil, "192.168.0.1"}, // no scope → private default
		{detector.KindIP, 7, nil, "192.168.0.7"},
		{detector.KindIP, 300, nil, "192.168.1.44"},                              // private spreads past one octet, no overflow
		{detector.KindIP, 1, map[string]string{"scope": "public"}, "77.0.0.1"},   // public → 77/8
		{detector.KindIP, 258, map[string]string{"scope": "public"}, "77.0.1.2"}, // public spreads past one octet
		{detector.KindAddr, 2, map[string]string{"port": "5432"}, "192.168.0.2:5432"},
		{detector.KindAddr, 1, nil, "192.168.0.1:8080"}, // fallback port, private default
		{detector.KindAddr, 1, map[string]string{"scope": "public", "port": "443"}, "77.0.0.1:443"},
		{detector.KindHost, 3, nil, "myhost3.local"},
		{detector.KindFQDN, 1, nil, "service1.example.com"},
		{detector.KindUser, 1, nil, "user1"},
		{detector.KindEmail, 4, nil, "user4@example.com"},
		{detector.KindUUID, 1, nil, "00000000-0000-0000-0000-000000000001"},
		{detector.KindUUID, 99, nil, "00000000-0000-0000-0000-000000000099"},
		{detector.KindSID, 1, nil, "S-1-5-21-0-0-0-1"},
	}
	for _, c := range cases {
		got := r.Generate(c.kind, c.n, c.extra)
		if got != c.want {
			t.Errorf("%s n=%d: got %q want %q", c.kind, c.n, got, c.want)
		}
	}
}

func TestGenerate_Stable(t *testing.T) {
	r := New()
	a := r.Generate(detector.KindIP, 5, nil)
	b := r.Generate(detector.KindIP, 5, nil)
	if a != b {
		t.Errorf("not stable: %q vs %q", a, b)
	}
}

func TestGenerate_DSN_PreservesScheme(t *testing.T) {
	r := New()
	got := r.Generate(detector.KindDSN, 1, map[string]string{
		"scheme": "redis",
		"port":   "6379",
	})
	if !strings.HasPrefix(got, "redis://") {
		t.Errorf("scheme not preserved: %q", got)
	}
	if !strings.Contains(got, ":6379/") {
		t.Errorf("port not preserved: %q", got)
	}
}

func TestGenerate_PortCycles(t *testing.T) {
	r := New()
	got1 := r.Generate(detector.KindPort, 1, nil)
	got7 := r.Generate(detector.KindPort, 7, nil) // wraps around (6 ports in pool)
	if got1 != got7 {
		t.Errorf("port should wrap: n=1 %q vs n=7 %q", got1, got7)
	}
}
