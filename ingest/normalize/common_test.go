package normalize

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Ported from tests/test_normalize_common.py (same cases).

func TestUnifyAliasesMapsVendorNamesToSchema(t *testing.T) {
	got := UnifyAliases(map[string]any{"ip": "1.2.3.4", "dst": "5.6.7.8", "spt": "1", "dpt": "2", "proto": "tcp"})
	want := map[string]any{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": "1", "dst_port": "2", "protocol": "tcp"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		eq(t, got[k], v)
	}
}

func TestUnifyAliasesExplicitSchemaKeyWins(t *testing.T) {
	eq(t, UnifyAliases(map[string]any{"src_ip": "1.1.1.1", "ip": "2.2.2.2"})["src_ip"], any("1.1.1.1"))
	eq(t, UnifyAliases(map[string]any{"ip": "2.2.2.2", "src_ip": "1.1.1.1"})["src_ip"], any("1.1.1.1"))
}

func TestCleanIP(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"10.0.0.1", "10.0.0.1"}, {"203.0.113.120:51515", "203.0.113.120"},
		{"[2001:db8::1]:443", "2001:db8::1"}, {"2001:db8::1", "2001:db8::1"},
		{"-", "<nil>"}, {"", "<nil>"}, {nil, "<nil>"}, {"ec2.amazonaws.com", "<nil>"},
	}
	for _, c := range cases {
		eq(t, s(CleanIP(c.in)), c.want)
	}
}

func TestToPort(t *testing.T) {
	cases := []struct {
		in   any
		want int
	}{{"443", 443}, {"0", -1}, {"-", -1}, {"70000", -1}, {json.Number("22"), 22}}
	for _, c := range cases {
		eq(t, i(ToPort(c.in)), c.want)
	}
}

func TestParseTSVariantsAllUTC(t *testing.T) {
	want := utc(2026, 10, 12, 8, 0, 0)
	for _, v := range []any{"2026-10-12T08:00:00Z", "2026-10-12T08:00:00", "2026-10-12T10:00:00+02:00",
		json.Number("1791792000"), json.Number("1791792000000")} {
		got, err := ParseTS(v)
		if err != nil || !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("ParseTS(%v) = %v, %v", v, got, err)
		}
	}
}

func TestParseTSRejectsMissing(t *testing.T) {
	if _, err := ParseTS(nil); err == nil {
		t.Error("want an error")
	}
}

func TestEventRejectsOutOfRangeSeverity(t *testing.T) {
	e := &Event{TS: time.Now(), Tenant: "t", Source: "api", Severity: ptr(11), Raw: map[string]any{}}
	if e.Validate() == nil {
		t.Error("want an error")
	}
}

func TestEventRejectsInvalidIP(t *testing.T) {
	e := &Event{TS: time.Now(), Tenant: "t", Source: "api", SrcIP: ptr("not-an-ip"), Raw: map[string]any{}}
	if e.Validate() == nil {
		t.Error("want an error")
	}
}

func TestRegistryRejectsUnknownSource(t *testing.T) {
	_, err := Normalize("mainframe", map[string]any{}, "t", NOW)
	if err == nil || !strings.Contains(err.Error(), "unknown source") {
		t.Errorf("got %v", err)
	}
}

// From tests/test_schema.py: the source list is enforced before anything is stored.
func TestUnknownSourceIsRejectedByValidation(t *testing.T) {
	e := &Event{TS: time.Now(), Tenant: "t-test", Source: "mainframe", Raw: map[string]any{}}
	if e.Validate() == nil {
		t.Error("want an error")
	}
}
