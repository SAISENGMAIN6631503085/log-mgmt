package normalize

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Same fixed "current time" as the Python tests had, so syslog year inference is deterministic.
var NOW = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func samplePath(name string) string { return filepath.Join("..", "..", "samples", name) }

func sampleLines(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(samplePath(name))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimRight(l, "\r"))
		}
	}
	return out
}

func decode(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func sampleJSON(t *testing.T, name string) any {
	data, err := os.ReadFile(samplePath(name))
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, data)
}

func sampleNDJSON(t *testing.T, name string) []any {
	f, err := os.Open(samplePath(name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			out = append(out, decode(t, sc.Bytes()))
		}
	}
	return out
}

func sampleCSV(t *testing.T, name string) []any {
	f, err := os.Open(samplePath(name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []any
	for _, r := range recs[1:] {
		row := map[string]any{}
		for i, h := range recs[0] {
			row[strings.TrimPrefix(h, "\ufeff")] = r[i]
		}
		out = append(out, row)
	}
	return out
}

// must normalizes and fails the test on error.
func must(t *testing.T, fn Func, payload any, tenant string, now time.Time) *Event {
	t.Helper()
	e, err := fn(payload, tenant, now)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return e
}

// s and i read optional fields for comparisons (nil -> "<nil>" / -1).
func s(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func i(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func hasTag(e *Event, tag string) bool {
	for _, x := range e.Tags {
		if x == tag {
			return true
		}
	}
	return false
}

func utc(y int, mo time.Month, d, h, mi, sec int) time.Time {
	return time.Date(y, mo, d, h, mi, sec, 0, time.UTC)
}

// joined prints values separated by single spaces (fmt.Sprint adds none between strings).
func joined(vals ...any) string { return strings.TrimSuffix(fmt.Sprintln(vals...), "\n") }

func eq[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
