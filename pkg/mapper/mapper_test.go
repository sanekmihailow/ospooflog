package mapper

import (
	"sync"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

func TestObfuscate_Stable(t *testing.T) {
	m := New(replacer.New())
	t1, r1 := m.Obfuscate("10.1.2.3", detector.KindIP, nil)
	t2, r2 := m.Obfuscate("10.1.2.3", detector.KindIP, nil)
	if t1 != t2 || r1 != r2 {
		t.Errorf("not stable: (%s,%s) vs (%s,%s)", t1, r1, t2, r2)
	}
}

func TestObfuscate_CounterPerKind(t *testing.T) {
	m := New(replacer.New())
	_, r1 := m.Obfuscate("10.1.2.3", detector.KindIP, nil)
	_, r2 := m.Obfuscate("10.4.5.6", detector.KindIP, nil)
	_, r3 := m.Obfuscate("alice", detector.KindUser, nil)
	if r1 != "192.168.1.1" || r2 != "192.168.1.2" {
		t.Errorf("ip counters: %q %q", r1, r2)
	}
	if r3 != "user1" {
		t.Errorf("user counter: %q", r3)
	}
}

func TestObfuscate_TokenFormat(t *testing.T) {
	m := New(replacer.New())
	tk, _ := m.Obfuscate("10.1.2.3", detector.KindIP, nil)
	if tk != "IP_001" {
		t.Errorf("token: %q", tk)
	}
}

func TestRestore(t *testing.T) {
	m := New(replacer.New())
	_, r := m.Obfuscate("alice", detector.KindUser, nil)
	got, ok := m.Restore(r)
	if !ok || got != "alice" {
		t.Errorf("restore failed: %q ok=%v", got, ok)
	}
	if _, ok := m.Restore("bogus"); ok {
		t.Errorf("unknown replace should not resolve")
	}
}

func TestLoad_ResumesCounters(t *testing.T) {
	m := New(replacer.New())
	m.Load([]Entry{
		{Token: "IP_005", Kind: detector.KindIP, Origin: "1.1.1.1", Replace: "192.168.1.5"},
	})
	_, r := m.Obfuscate("2.2.2.2", detector.KindIP, nil)
	if r != "192.168.1.6" {
		t.Errorf("counter not resumed past loaded entries: got %q", r)
	}
}

func TestLoad_PreservesByReplaceLookup(t *testing.T) {
	m := New(replacer.New())
	m.Load([]Entry{
		{Token: "USER_001", Kind: detector.KindUser, Origin: "alice", Replace: "user1"},
	})
	got, ok := m.Restore("user1")
	if !ok || got != "alice" {
		t.Errorf("loaded entry not restorable: %q ok=%v", got, ok)
	}
}

func TestObfuscate_ConcurrentSafe(t *testing.T) {
	m := New(replacer.New())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Obfuscate("10.1.2.3", detector.KindIP, nil)
		}()
	}
	wg.Wait()
	if got := len(m.Entries()); got != 1 {
		t.Errorf("concurrent obfuscates of same origin should produce 1 entry, got %d", got)
	}
}
