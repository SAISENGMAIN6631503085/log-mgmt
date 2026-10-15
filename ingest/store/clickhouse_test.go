package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"logmgmt/ingest/normalize"
)

// Ported from tests/test_clickhouse_store.py. The unit tests always run; the ones that talk to
// ClickHouse need CLICKHOUSE_URL (set by `make test`) and are skipped without it.

func event(tenant string, raw map[string]any) *normalize.Event {
	return &normalize.Event{TS: time.Now().UTC(), Tenant: tenant, Source: "api", Raw: raw}
}

func TestFingerprintIgnoresKeyOrder(t *testing.T) {
	var a, b map[string]any
	_ = json.Unmarshal([]byte(`{"a":1,"b":{"x":1,"y":2}}`), &a)
	_ = json.Unmarshal([]byte(`{"b":{"y":2,"x":1},"a":1}`), &b)
	if Fingerprint(event("t", a)) != Fingerprint(event("t", b)) {
		t.Error("same content must give the same fingerprint")
	}
	if Fingerprint(event("t", a)) == Fingerprint(event("other", a)) {
		t.Error("the tenant is part of the fingerprint")
	}
}

func TestFingerprintMatchesPythonsJSON(t *testing.T) {
	// Events stored by the earlier Python version must still count as duplicates, so the text
	// that gets hashed is exactly Python's json.dumps(..., sort_keys=True, separators=(",", ":")):
	// sorted keys, no spaces, non-ASCII as \uXXXX, and <, >, & left as they are.
	e := event("demoA", map[string]any{"user": "zo\u00eb", "msg": "<b>&", "emoji": "\U0001F600"})
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode([]any{e.Tenant, e.Source, e.Raw})
	got := asciiOnly(strings.TrimSuffix(buf.String(), "\n"))
	want := `["demoA","api",{"emoji":"\ud83d\ude00","msg":"<b>&","user":"zo\u00eb"}]`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestIDsAreUniqueIncreasingAndSafeInJavaScript(t *testing.T) {
	ids := make([]uint64, 20_000) // more than fit in one millisecond
	for i := range ids {
		ids[i] = NewID()
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("ids must only go up: %d after %d", ids[i], ids[i-1])
		}
	}
	if ids[len(ids)-1] >= 1<<53 {
		t.Error("JSON numbers in browsers are exact only up to 2^53")
	}
}

func TestArrayParamQuoting(t *testing.T) {
	if got := arrayParam([]string{"a", "o'brien", `back\slash`}); got != `['a','o\'brien','back\\slash']` {
		t.Errorf("got %s", got)
	}
	if got := msTime(time.Date(2026, 10, 12, 8, 0, 1, 123456789, time.UTC)); got != "2026-10-12 08:00:01.123" {
		t.Errorf("got %s", got)
	}
}

// --- against ClickHouse ---

func clickhouse(t *testing.T) (*ClickHouse, string) {
	t.Helper()
	url := os.Getenv("CLICKHOUSE_URL")
	if url == "" {
		t.Skip("CLICKHOUSE_URL not set; run `make test`")
	}
	c := New(url, os.Getenv("CLICKHOUSE_DB"), os.Getenv("CLICKHOUSE_USER"), os.Getenv("CLICKHOUSE_PASSWORD"))
	if !c.Ping(context.Background()) {
		t.Skip("ClickHouse not reachable; run `make up` first")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	tenant := "gos_" + hex.EncodeToString(b)
	// One cheap delete after the test, not waited for: a ClickHouse DELETE rewrites files in the
	// background, and the tenant name is random, so leftovers can't affect anything else.
	t.Cleanup(func() {
		_, _ = c.post(context.Background(), "DELETE FROM events WHERE tenant = {t:String} SETTINGS lightweight_deletes_sync = 0",
			map[string]string{"param_t": tenant}, nil)
	})
	return c, tenant
}

func count(t *testing.T, c *ClickHouse, tenant string) int {
	out, err := c.post(context.Background(), "SELECT count() FROM events FINAL WHERE tenant = {t:String}",
		map[string]string{"param_t": tenant}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func TestNewAndRepeatedEvents(t *testing.T) {
	c, tenant := clickhouse(t)
	ctx := context.Background()
	evs := []*normalize.Event{event(tenant, map[string]any{"n": 1}), event(tenant, map[string]any{"n": 2})}
	if n, err := c.Insert(ctx, evs); err != nil || n != 2 {
		t.Fatalf("first insert: %d, %v", n, err)
	}
	if n, err := c.Insert(ctx, evs); err != nil || n != 0 {
		t.Fatalf("repeat: %d, %v", n, err)
	}
	if got := count(t, c, tenant); got != 2 {
		t.Errorf("stored %d", got)
	}
}

func TestBigBatchIsCheckedInChunks(t *testing.T) {
	c, tenant := clickhouse(t)
	var evs []*normalize.Event
	for i := 0; i < CheckChunk*2+50; i++ { // more fingerprints than fit in one URL
		evs = append(evs, event(tenant, map[string]any{"i": i}))
	}
	if n, err := c.Insert(context.Background(), evs); err != nil || n != len(evs) {
		t.Fatalf("first: %d, %v", n, err)
	}
	if n, err := c.Insert(context.Background(), evs); err != nil || n != 0 {
		t.Fatalf("repeat: %d, %v", n, err)
	}
}

func TestRepeatsInsideOneBatchCountOnce(t *testing.T) {
	c, tenant := clickhouse(t)
	e := event(tenant, map[string]any{"same": true})
	if n, err := c.Insert(context.Background(), []*normalize.Event{e, e, e}); err != nil || n != 1 {
		t.Fatalf("%d, %v", n, err)
	}
	if got := count(t, c, tenant); got != 1 {
		t.Errorf("stored %d", got)
	}
}

func TestSameContentAtAnotherTimeIsANewEvent(t *testing.T) {
	// A duplicate is the same fingerprint at the same time, not just the same content.
	c, tenant := clickhouse(t)
	a := event(tenant, map[string]any{"x": 1})
	b := *a
	b.TS = a.TS.Add(5 * time.Second)
	if n, _ := c.Insert(context.Background(), []*normalize.Event{a, &b}); n != 2 {
		t.Fatalf("first: %d", n)
	}
	if n, _ := c.Insert(context.Background(), []*normalize.Event{a, &b}); n != 0 {
		t.Fatalf("repeat: %d", n)
	}
	if got := count(t, c, tenant); got != 2 {
		t.Errorf("stored %d", got)
	}
}

func TestTimeAdjustedEventSentAgainLaterIsADuplicate(t *testing.T) {
	// An old log is stored at its receipt time (tag time_adjusted), so each send has a different
	// stored time; re-uploading the same old file must still count as duplicates.
	c, tenant := clickhouse(t)
	first := event(tenant, map[string]any{"eventTime": "2025-08-20T09:10:00Z", "eventName": "CreateUser"})
	first.Tags = []string{normalize.TimeAdjusted}
	again := *first
	again.TS = first.TS.Add(3 * time.Minute) // the second upload, a few minutes later
	if n, _ := c.Insert(context.Background(), []*normalize.Event{first}); n != 1 {
		t.Fatalf("first: %d", n)
	}
	if n, _ := c.Insert(context.Background(), []*normalize.Event{&again}); n != 0 {
		t.Fatalf("the same old log sent again was stored again (%d)", n)
	}
	// A different old log is still new.
	other := *first
	other.Raw = map[string]any{"eventTime": "2025-08-20T09:11:00Z", "eventName": "CreateUser"}
	if n, _ := c.Insert(context.Background(), []*normalize.Event{&other}); n != 1 {
		t.Fatalf("a different old log: %d", n)
	}
}

func TestStoredRowReadsBackWithAllFields(t *testing.T) {
	c, tenant := clickhouse(t)
	ip, country, port := "1.46.10.5", "TH", 443
	e := event(tenant, map[string]any{"k": "v"})
	e.SrcIP, e.SrcCountry, e.DstPort, e.Tags = &ip, &country, &port, []string{"auth_failure"}
	if _, err := c.Insert(context.Background(), []*normalize.Event{e}); err != nil {
		t.Fatal(err)
	}
	out, err := c.post(context.Background(), "SELECT src_ip, src_country, dst_port, tags, raw, id < pow(2, 53) AS safe "+
		"FROM events WHERE tenant = {t:String} FORMAT JSONEachRow", map[string]string{"param_t": tenant}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		SrcIP      string   `json:"src_ip"`
		SrcCountry string   `json:"src_country"`
		DstPort    int      `json:"dst_port"`
		Tags       []string `json:"tags"`
		Raw        string   `json:"raw"`
		Safe       int      `json:"safe"`
	}
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if row.SrcIP != ip || row.SrcCountry != "TH" || row.DstPort != 443 || len(row.Tags) != 1 || row.Raw != `{"k":"v"}` || row.Safe != 1 {
		t.Errorf("read back %+v", row)
	}
}
