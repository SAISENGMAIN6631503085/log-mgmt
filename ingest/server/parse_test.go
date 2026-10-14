package server

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Ported from tests/test_ingest_parsing.py (same cases).

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func TestParseEverySampleFile(t *testing.T) {
	cases := []struct {
		name, source string
		count        int
	}{
		{"aws_cloudtrail.json", "aws", 6}, // {"Records": [...]} unwrapped
		{"m365_audit.json", "m365", 4},
		{"api_events.json", "api", 5},
		{"crowdstrike_detections.ndjson", "crowdstrike", 2},
		{"ad_security.csv", "ad", 11},
		{"firewall.log", "firewall", 5},
		{"network.log", "network", 4},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join("..", "..", "samples", c.name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseUpload(c.name, data, c.source)
		if err != nil || len(got) != c.count {
			t.Errorf("%s: %d items, %v; want %d", c.name, len(got), err, c.count)
		}
	}
}

func TestCSVWithExcelBOM(t *testing.T) {
	rows, err := ParseUpload("x.csv", []byte("\xef\xbb\xbfEventID,Computer\n4625,DC01\n"), "ad")
	want := []any{map[string]any{"EventID": "4625", "Computer": "DC01"}}
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Errorf("got %v, %v", rows, err)
	}
}

func TestNDJSONSavedAsJSON(t *testing.T) {
	rows, err := ParseUpload("x.json", []byte("{\"a\":1}\n{\"a\":2}\n"), "api")
	if err != nil || len(rows) != 2 {
		t.Errorf("got %v, %v", rows, err)
	}
}

func TestSingleJSONObjectFile(t *testing.T) {
	rows, err := ParseUpload("x.json", []byte(`{"a":1}`), "api")
	if err != nil || len(rows) != 1 || rows[0].(map[string]any)["a"].(interface{ String() string }).String() != "1" {
		t.Errorf("got %v, %v", rows, err)
	}
}

func TestUnknownExtensionRejected(t *testing.T) {
	_, err := ParseUpload("x.bin", []byte("\x00garbage"), "api")
	if err == nil || !strings.Contains(err.Error(), "unsupported file type") {
		t.Errorf("got %v", err)
	}
}

func TestSplitPayloads(t *testing.T) {
	one, _ := SplitPayloads("api", map[string]any{"a": 1})
	two, _ := SplitPayloads("api", []any{map[string]any{"a": 1}, map[string]any{"a": 2}})
	recs, _ := SplitPayloads("aws", map[string]any{"Records": []any{map[string]any{"x": 1}}})
	if len(one) != 1 || len(two) != 2 || !reflect.DeepEqual(recs, []any{map[string]any{"x": 1}}) {
		t.Errorf("got %v %v %v", one, two, recs)
	}
	if _, err := SplitPayloads("api", 42); err == nil {
		t.Error("a number must be rejected")
	}
}

func TestClassifySyslog(t *testing.T) {
	cases := map[string]string{
		"<134>Oct 12 08:00:00 fw01 action=deny src=1.2.3.4 dst=5.6.7.8":        "firewall",
		"<134>Oct 12 08:00:00 fw01 action=accept ip=1.2.3.4":                   "firewall",
		"<187>Oct 12 08:00:00 sw %LINK-3-UPDOWN: event_type=link_down":         "network",
		"<189>Oct 12 08:00:00 rtr event_type=config_change user=x src=1.2.3.4": "network", // no action
		"garbage": "network",
	}
	for line, want := range cases {
		if got := ClassifySyslog(line); got != want {
			t.Errorf("%q: got %s, want %s", line, got, want)
		}
	}
}

func TestTSWindow(t *testing.T) {
	day := 24 * time.Hour
	if CheckTSWindow(now, 7, now) != "" || CheckTSWindow(now.Add(-6*day), 7, now) != "" {
		t.Error("times inside the window must pass")
	}
	if !strings.Contains(CheckTSWindow(now.Add(-8*day), 7, now), "retention") {
		t.Error("too old")
	}
	if !strings.Contains(CheckTSWindow(now.Add(2*day), 7, now), "future") {
		t.Error("too far ahead")
	}
}
