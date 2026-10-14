// Package normalize turns one raw log (a syslog line or a JSON object) from any source into the
// common schema (Event). One file per source; every normalizer is a pure function of
// (payload, tenant, now), so each one is unit-tested with literal samples.
package normalize

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthFailure is the tag the brute-force alert rule looks for.
const AuthFailure = "auth_failure"

// Sources and actions allowed by the common schema.
var (
	Sources = []string{"ad", "api", "aws", "crowdstrike", "firewall", "m365", "network"}
	actions = map[string]bool{"allow": true, "deny": true, "create": true, "delete": true,
		"login": true, "logout": true, "alert": true, "quarantine": true}
)

// Event is one normalized event. Optional fields are pointers: nil means "not in this log",
// which is stored as NULL (an empty string or 0 would look like a real value).
type Event struct {
	TS             time.Time
	Tenant         string
	Source         string
	Vendor         *string
	Product        *string
	EventType      *string
	EventSubtype   *string
	Severity       *int
	Action         *string
	SrcIP          *string
	SrcPort        *int
	DstIP          *string
	DstPort        *int
	Protocol       *string
	User           *string
	Host           *string
	Process        *string
	URL            *string
	HTTPMethod     *string
	StatusCode     *int
	RuleName       *string
	RuleID         *string
	CloudAccountID *string
	CloudRegion    *string
	CloudService   *string
	SrcCountry     *string // enrichment, set at ingest from SrcIP, never by a normalizer
	Raw            map[string]any
	Tags           []string
}

// Validate is the last line of defence: a normalizer bug that produces e.g. severity 42 fails
// loudly in tests instead of being stored.
func (e *Event) Validate() error {
	if e.TS.IsZero() {
		return errors.New("@timestamp: missing")
	}
	if e.Tenant == "" {
		return errors.New("tenant: missing")
	}
	if !contains(Sources, e.Source) {
		return fmt.Errorf("source: %q is not one of %v", e.Source, Sources)
	}
	if e.Action != nil && !actions[*e.Action] {
		return fmt.Errorf("action: %q is not allowed", *e.Action)
	}
	if e.Severity != nil && (*e.Severity < 0 || *e.Severity > 10) {
		return fmt.Errorf("severity: %d is outside 0-10", *e.Severity)
	}
	for name, v := range map[string]*int{"src_port": e.SrcPort, "dst_port": e.DstPort, "status_code": e.StatusCode} {
		if v != nil && (*v < 0 || *v > 65535) {
			return fmt.Errorf("%s: %d is outside 0-65535", name, *v)
		}
	}
	for name, v := range map[string]*string{"src_ip": e.SrcIP, "dst_ip": e.DstIP} {
		if v != nil {
			if _, err := netip.ParseAddr(*v); err != nil {
				return fmt.Errorf("%s: %q is not an IP address", name, *v) // normalizers should use CleanIP
			}
		}
	}
	if e.SrcCountry != nil && len(*e.SrcCountry) != 2 {
		return fmt.Errorf("src_country: %q is not a two-letter code", *e.SrcCountry)
	}
	if e.Raw == nil {
		return errors.New("raw: missing")
	}
	return nil
}

// --- small helpers shared by the normalizers -------------------------------------------

// aliases maps field names seen across vendors to the common schema names.
var aliases = map[string]string{
	"ip": "src_ip", "src": "src_ip", "srcip": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip",
	"dst": "dst_ip", "dstip": "dst_ip", "destination_ip": "dst_ip",
	"spt": "src_port", "sport": "src_port", "srcport": "src_port",
	"dpt": "dst_port", "dport": "dst_port", "dstport": "dst_port",
	"proto": "protocol",
}

// UnifyAliases renames alias keys to schema names. An explicit schema key always wins over an
// alias; if two aliases name the same field, the first in sorted key order wins (Go maps have
// no order of their own, so sorting keeps the result the same on every run).
func UnifyAliases(d map[string]any) map[string]any {
	out := make(map[string]any, len(d))
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys { // explicit names first, so they win
		if _, isAlias := aliases[strings.ToLower(k)]; !isAlias {
			out[k] = d[k]
		}
	}
	for _, k := range keys {
		if target, isAlias := aliases[strings.ToLower(k)]; isAlias {
			if _, taken := out[target]; !taken {
				out[target] = d[k]
			}
		}
	}
	return out
}

// truthy follows Python's idea of "has a value": nil, "", 0, false and empty lists/objects don't.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case int:
		return x != 0
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	}
	return true
}

// first returns the first value that has something in it ("a or b or c").
func first(vals ...any) any {
	for _, v := range vals {
		if truthy(v) {
			return v
		}
	}
	return nil
}

// text turns a scalar into text; nil, "" and objects/lists give nil (the raw log keeps them).
func text(v any) *string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		s = strconv.Itoa(x)
	case bool:
		s = strconv.FormatBool(x)
	default:
		return nil
	}
	if s == "" {
		return nil
	}
	return &s
}

// str is text() as a plain string ("" for nothing), for comparisons.
func str(v any) string {
	if p := text(v); p != nil {
		return *p
	}
	return ""
}

func ptr[T any](v T) *T { return &v }

// strOrNil gives nil for an empty string.
func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var empty = map[string]bool{"": true, "-": true, "n/a": true, "N/A": true}

// BlankToNil: logs use many spellings of "no value" ('-' in Windows CSVs, "" in JSON).
func BlankToNil(v any) any {
	if s, ok := v.(string); ok && empty[strings.TrimSpace(s)] {
		return nil
	}
	return v
}

// ToInt reads a whole number from a JSON number or text; anything else is nil.
func ToInt(v any) *int {
	switch x := BlankToNil(v).(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return ptr(int(i))
		}
		if f, err := x.Float64(); err == nil && !math.IsInf(f, 0) {
			return ptr(int(f)) // 4.7 -> 4, like Python's int()
		}
	case float64:
		return ptr(int(x))
	case int:
		return ptr(x)
	case bool:
		if x {
			return ptr(1)
		}
		return ptr(0)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return &i
		}
	}
	return nil
}

// ToPort: port 0 means "not applicable" in Windows logs, so treat it as missing.
func ToPort(v any) *int {
	p := ToInt(v)
	if p != nil && *p > 0 && *p <= 65535 {
		return p
	}
	return nil
}

// CleanIP returns a valid IP or nil. Logs put hostnames, "ip:port" and "-" in IP fields; one
// junk field shouldn't make us drop the whole event.
func CleanIP(v any) *string {
	s, ok := BlankToNil(v).(string)
	if !ok {
		return nil
	}
	s = strings.Trim(strings.TrimSpace(s), "[]")
	candidates := []string{s}
	if i := strings.LastIndex(s, ":"); i >= 0 { // second try strips ":port"
		candidates = append(candidates, strings.Trim(s[:i], "[]"))
	}
	for _, c := range candidates {
		if a, err := netip.ParseAddr(c); err == nil {
			return ptr(a.String())
		}
	}
	return nil
}

// isoLayouts are the ISO-8601 forms seen in logs: with or without a zone, "T" or a space,
// optional fractions (Go accepts a fraction after the seconds even when the layout has none).
var isoLayouts = []string{
	"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05Z0700", "2006-01-02 15:04:05",
	"2006-01-02T15:04", "2006-01-02",
}

// ParseTS reads ISO-8601 text (a missing zone means UTC) and epoch seconds or milliseconds.
func ParseTS(v any) (time.Time, error) {
	switch x := v.(type) {
	case json.Number, float64, int:
		f, err := strconv.ParseFloat(fmt.Sprint(x), 64)
		if err != nil {
			break
		}
		// Epoch in ms is > 1e11 for any date after 1973; seconds won't reach that until year 5138.
		if f > 1e11 {
			f /= 1000
		}
		return time.UnixMicro(int64(math.Round(f * 1e6))).UTC(), nil
	case string:
		s := strings.ReplaceAll(strings.TrimSpace(x), "Z", "+00:00")
		for _, layout := range isoLayouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC(), nil // time.Parse reads a zone-less time as UTC
			}
		}
	}
	return time.Time{}, fmt.Errorf("missing or unparseable timestamp: %v", v)
}

// flatTime is the timestamp in the flat sample format used in the assignment.
func flatTime(d map[string]any) any {
	return first(d["@timestamp"], d["timestamp"], d["time"])
}

// flatCloud accepts {"cloud": {"service": ...}} and flat cloud_service / cloud.service keys.
func flatCloud(d map[string]any) (service, accountID, region any) {
	c, _ := d["cloud"].(map[string]any)
	return first(c["service"], d["cloud_service"], d["cloud.service"]),
		first(c["account_id"], d["cloud_account_id"], d["cloud.account_id"]),
		first(c["region"], d["cloud_region"], d["cloud.region"])
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// object is a payload that must be a JSON object (every source except the syslog ones).
func object(payload any) (map[string]any, error) {
	d, ok := payload.(map[string]any)
	if !ok {
		return nil, errors.New("event must be a JSON object")
	}
	return d, nil
}

// get reads a nested object, treating anything else as empty.
func get(d map[string]any, key string) map[string]any {
	m, _ := d[key].(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
