// Package store writes normalized events to ClickHouse over its HTTP interface (port 8123).
//
// Values never go into the SQL text: queries use ClickHouse's typed placeholders, e.g.
// `WHERE tenant IN {tenants:Array(String)}`, and the values travel separately as
// `param_tenants=...`, so log content can't inject SQL.
package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"logmgmt/ingest/normalize"
)

// CheckChunk is how many fingerprints go into one duplicate-check query (~20 KB of URL):
// parameters travel in the URL, and thousands at once would exceed its length limit.
const CheckChunk = 300

type ClickHouse struct {
	URL, Database, User, Password string
	HTTP                          *http.Client
}

func New(baseURL, database, user, password string) *ClickHouse {
	return &ClickHouse{URL: strings.TrimRight(baseURL, "/"), Database: database, User: user,
		Password: password, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// post sends one statement; query settings and parameters go in the URL, data in the body.
func (c *ClickHouse) post(ctx context.Context, query string, params map[string]string, body []byte) ([]byte, error) {
	q := url.Values{"query": {query}, "database": {c.Database}}
	for k, v := range params {
		q.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Password)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ClickHouse error %d: %.500s", resp.StatusCode, out)
	}
	return out, nil
}

// Ping is true if ClickHouse answers a trivial query.
func (c *ClickHouse) Ping(ctx context.Context) bool {
	_, err := c.post(ctx, "SELECT 1", nil, nil)
	return err == nil
}

// Insert stores the batch and returns how many events were new.
//
// A duplicate is the same fingerprint at the same time: the same log content at a different time
// is a new event. Except for events stored at their receipt time because their own time was out of
// range (tag time_adjusted): their stored time changes with every send, so for them the
// fingerprint alone decides, matched against any stored copy (whether that copy was stored
// time-adjusted or, while its time was still recent, normally). That's safe because their real
// time is part of the original log, which the fingerprint covers; without it, re-uploading an
// old file would store it again. ClickHouse
// has no unique constraint, so existing (fingerprint, ts) pairs are looked up first; that keeps
// counts right at once and lets ingest report "duplicates". The pair is also the table's
// ORDER BY key, so ReplacingMergeTree removes any repeat that slips through when it merges.
func (c *ClickHouse) Insert(ctx context.Context, events []*normalize.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	type key struct{ fp, ts string }
	const adjustedTS = "adjusted" // the "time" in the key of a time-adjusted event: any time matches
	var order []key
	batch := map[key]*normalize.Event{}
	tenants, fps := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		k := key{Fingerprint(e), msTime(e.TS)}
		if hasTag(e, normalize.TimeAdjusted) {
			k.ts = adjustedTS
		}
		if _, seen := batch[k]; !seen { // repeats inside one batch count once
			batch[k] = e
			order = append(order, k)
			tenants[e.Tenant], fps[k.fp] = true, true
		}
	}
	fpList := sortedKeys(fps)
	stored := map[key]bool{}
	for i := 0; i < len(fpList); i += CheckChunk {
		chunk := fpList[i:min(i+CheckChunk, len(fpList))]
		out, err := c.post(ctx,
			"SELECT DISTINCT fingerprint, toString(ts) AS ts FROM events "+
				"WHERE tenant IN {tenants:Array(String)} AND fingerprint IN {fps:Array(String)} FORMAT JSONEachRow",
			map[string]string{"param_tenants": arrayParam(sortedKeys(tenants)), "param_fps": arrayParam(chunk)}, nil)
		if err != nil {
			return 0, err
		}
		for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
			var r struct{ Fingerprint, Ts string }
			if len(line) > 0 && json.Unmarshal(line, &r) == nil {
				stored[key{r.Fingerprint, r.Ts}] = true
				stored[key{r.Fingerprint, adjustedTS}] = true // any stored copy covers a time-adjusted resend
			}
		}
	}
	var body bytes.Buffer
	n := 0
	for _, k := range order {
		if stored[k] {
			continue
		}
		line, err := json.Marshal(row(batch[k], k.fp))
		if err != nil {
			return 0, err
		}
		body.Write(line)
		body.WriteByte('\n')
		n++
	}
	if n == 0 {
		return 0, nil
	}
	_, err := c.post(ctx, "INSERT INTO events FORMAT JSONEachRow",
		map[string]string{"date_time_input_format": "best_effort"}, body.Bytes())
	if err != nil {
		return 0, err
	}
	return n, nil
}

// row is one events-table row as JSON (column names from the ClickHouse schema in the backend).
func row(e *normalize.Event, fp string) map[string]any {
	raw, _ := json.Marshal(e.Raw)
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	return map[string]any{
		"id": NewID(), "ts": e.TS.UTC().Format(time.RFC3339Nano), "tenant": e.Tenant, "source": e.Source,
		"vendor": e.Vendor, "product": e.Product, "event_type": e.EventType, "event_subtype": e.EventSubtype,
		"severity": e.Severity, "action": e.Action, "src_ip": e.SrcIP, "src_port": e.SrcPort,
		"dst_ip": e.DstIP, "dst_port": e.DstPort, "protocol": e.Protocol, "username": e.User,
		"host": e.Host, "process": e.Process, "url": e.URL, "http_method": e.HTTPMethod,
		"status_code": e.StatusCode, "rule_name": e.RuleName, "rule_id": e.RuleID,
		"cloud_account_id": e.CloudAccountID, "cloud_region": e.CloudRegion, "cloud_service": e.CloudService,
		"src_country": e.SrcCountry, "raw": string(raw), "tags": tags, "fingerprint": fp,
	}
}

func hasTag(e *normalize.Event, tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// msTime is the time as ClickHouse prints a DateTime64(3): milliseconds, UTC.
func msTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02 15:04:05.000")
}

// Fingerprint is the sha256 of tenant + source + original payload as JSON with sorted keys, so
// the same log hashes the same however its JSON was formatted. Non-ASCII characters are written
// as \uXXXX, like Python's json.dumps, so events stored by the earlier Python version of this
// service still count as duplicates.
func Fingerprint(e *normalize.Event) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep <, > and & as they are, as Python does
	_ = enc.Encode([]any{e.Tenant, e.Source, e.Raw})
	sum := sha256.Sum256([]byte(asciiOnly(strings.TrimSuffix(buf.String(), "\n"))))
	return hex.EncodeToString(sum[:])
}

func asciiOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case r > 0xFFFF: // outside the basic plane: a UTF-16 surrogate pair
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// Ids must fit in 53 bits: browsers keep JSON numbers as doubles, which are exact only up to
// 2^53, so a bigger id could come back changed and open the wrong event. Layout: milliseconds
// since 1970 (41 bits, good until 2039) shifted left by 12, plus a counter. The id only ever goes
// up, even for a 10,000-event batch inside one millisecond: it then runs slightly ahead of the
// clock. Each process adds its own random offset, so two processes starting in the same
// millisecond are unlikely to hand out the same id.
var (
	idMu     sync.Mutex
	lastID   uint64
	idOffset = randomOffset()
)

func randomOffset() uint64 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return uint64(binary.BigEndian.Uint16(b[:]) & 0x7FF) // 11 bits
}

// NewID is unique within this process, increasing, roughly time-ordered, and exact in JavaScript.
func NewID() uint64 {
	idMu.Lock()
	defer idMu.Unlock()
	lastID = max(lastID+1, uint64(time.Now().UnixMilli())<<12+idOffset)
	return lastID
}

// arrayParam formats a list as a ClickHouse array literal: ['a','b'] with quotes and
// backslashes escaped.
func arrayParam(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
