package jsonproc

import (
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestFieldRules_Actions(t *testing.T) {
	rules := FieldRules{
		"headers.Authorization": {Action: ActionRemove},
		"msg":                   {Action: ActionKeep},
		"user.id":               {Action: ActionMask},
		"user.token":            {Action: ActionMaskAs, Kind: detector.KindAPIKey},
	}
	p := newProcRules(nil, rules)
	in := `{"headers":{"Authorization":"Bearer t"},"msg":"hi a@b.com","user":{"id":99213,"token":"raw"}}`
	out := p.processLine(in)

	if strings.Contains(out, "Authorization") {
		t.Errorf("remove should drop the field: %s", out)
	}
	if !strings.Contains(out, `"msg":"hi a@b.com"`) {
		t.Errorf("keep should leave the value verbatim (email not masked): %s", out)
	}
	if !strings.Contains(out, `"id":"FAKE_FIELD_1"`) {
		t.Errorf("mask should replace the whole value (number → fake): %s", out)
	}
	if strings.Contains(out, `"token":"raw"`) {
		t.Errorf("mask-as should replace the token value: %s", out)
	}
}

func TestFieldRules_ArrayTransparent(t *testing.T) {
	rules := FieldRules{"items.email": {Action: ActionMaskAs, Kind: detector.KindEmail}}
	p := newProcRules(nil, rules)
	in := `{"items":[{"email":"x@y.com"},{"email":"z@w.com"}]}`
	out := p.processLine(in)

	if strings.Contains(out, "x@y.com") || strings.Contains(out, "z@w.com") {
		t.Errorf("items.email should mask email in every array element: %s", out)
	}
}
