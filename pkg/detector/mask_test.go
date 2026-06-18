package detector

import "testing"

func TestChain_SetMask_FiltersEmittedKinds(t *testing.T) {
	text := "mail a@b.com from 10.0.0.1"

	all := New(DefaultRules()).Find(text)
	if len(all) != 2 {
		t.Fatalf("baseline: want EMAIL+IP, got %d: %+v", len(all), all)
	}

	c := New(DefaultRules())
	c.SetMask(map[EntityKind]bool{KindIP: true})
	got := c.Find(text)
	if len(got) != 1 || got[0].Kind != KindIP {
		t.Fatalf("masking to IP only: want one IP match, got %+v", got)
	}
	// The IP offset must be identical to the unfiltered run — proving the filter
	// is output-only and doesn't perturb detection/overlap resolution.
	for _, m := range all {
		if m.Kind == KindIP && m.Start != got[0].Start {
			t.Errorf("IP span shifted under mask: %d vs %d", got[0].Start, m.Start)
		}
	}
}

func TestChain_SetMask_NilMasksEverything(t *testing.T) {
	text := "mail a@b.com from 10.0.0.1"
	c := New(DefaultRules())
	c.SetMask(nil)
	if got := c.Find(text); len(got) != 2 {
		t.Errorf("nil filter should emit every kind, got %d", len(got))
	}
}
