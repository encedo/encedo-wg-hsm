package session

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBundleCarriesExpectOnceAndPutsUseFirst(t *testing.T) {
	a := &Auth{pending: []string{"keymgmt:get", "keymgmt:upd", "keymgmt:get"}}

	got := a.bundle("keymgmt:use:ab")
	if strings.Join(got, ",") != "keymgmt:use:ab,keymgmt:get,keymgmt:upd" {
		t.Errorf("first request = %v", got)
	}
	if got := a.bundle("keymgmt:del"); len(got) != 1 || got[0] != "keymgmt:del" {
		t.Errorf("a later request carried the expected scopes again: %v", got)
	}

	// Asked first for something else, the use scope still leads.
	b := &Auth{pending: []string{"keymgmt:use:cd", "keymgmt:get"}}
	if got := b.bundle("keymgmt:search"); got[0] != "keymgmt:use:cd" {
		t.Errorf("use scope not first: %v", got)
	}
}

func TestBundleStopsAtEight(t *testing.T) {
	var pending []string
	for i := 0; i < 12; i++ {
		pending = append(pending, "keymgmt:use:"+strings.Repeat(string(rune('a'+i)), 32))
	}
	a := &Auth{pending: pending}
	if got := a.bundle("keymgmt:get"); len(got) != 8 {
		t.Errorf("%d scopes in one request, the device takes at most 8", len(got))
	}
}

func jwtWith(scope interface{}) string {
	raw, _ := json.Marshal(map[string]interface{}{"scope": scope})
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// A phone may approve part of a request. A token without the scope that was
// asked for is refused here, by name, instead of by the device with a bare 403.
func TestCheckRefusesAPartialApproval(t *testing.T) {
	a := &Auth{}
	tok := jwtWith([]string{"keymgmt:get"})
	if _, err := a.check(tok, "keymgmt:use:ab"); err == nil || !strings.Contains(err.Error(), "keymgmt:use:ab") {
		t.Errorf("partial approval: %v", err)
	}
	if got, err := a.check(tok, "keymgmt:get"); err != nil || got != tok {
		t.Errorf("approved scope refused: %v", err)
	}
	if _, err := a.check("opaque", "keymgmt:get"); err != nil {
		t.Errorf("an unreadable token is the device's to judge: %v", err)
	}
}
