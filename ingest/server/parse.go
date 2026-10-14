package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"logmgmt/ingest/normalize"
)

// Turning request bodies and uploaded files into lists of raw payloads. Pure: no I/O.

var syslogSources = map[string]bool{"firewall": true, "network": true}

// decodeJSON keeps numbers exactly as written (json.Number), so ids and big integers in the
// original log are stored unchanged.
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("extra data after the JSON value")
	}
	return v, nil
}

// SplitPayloads: a JSON body may be one event, an array, or (AWS) a CloudTrail {"Records": [...]} file.
func SplitPayloads(source string, body any) ([]any, error) {
	if source == "aws" {
		return normalize.IterRecords(body)
	}
	switch x := body.(type) {
	case []any:
		return x, nil
	case map[string]any, string:
		return []any{x}, nil
	}
	return nil, errors.New("body must be a JSON object or array")
}

// ParseUpload detects the file format from its extension (falling back to sniffing the content).
// .csv -> one object per row; .ndjson/.jsonl -> one object per line; .json -> object/array;
// .log/.txt (or any text for syslog sources) -> one syslog line per line.
func ParseUpload(filename string, content []byte, source string) ([]any, error) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf")) // the BOM Excel/PowerShell exports add
	if !utf8.Valid(content) {
		return nil, errors.New("file is not UTF-8 text")
	}
	text := string(content)
	name := strings.ToLower(filename)
	var lines []string
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	switch {
	case strings.HasSuffix(name, ".csv"):
		return parseCSV(text)
	case strings.HasSuffix(name, ".ndjson"), strings.HasSuffix(name, ".jsonl"):
		return jsonLines(lines)
	case strings.HasSuffix(name, ".log"), strings.HasSuffix(name, ".txt"), syslogSources[source]:
		out := make([]any, len(lines))
		for i, l := range lines {
			out[i] = l
		}
		return out, nil
	case strings.HasSuffix(name, ".json"), strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "["),
		strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{"):
		if doc, err := decodeJSON(content); err == nil {
			return SplitPayloads(source, doc)
		}
		return jsonLines(lines) // NDJSON saved with a .json name
	}
	return nil, fmt.Errorf("unsupported file type: %q (use .json, .ndjson, .csv or .log)", filename)
}

func jsonLines(lines []string) ([]any, error) {
	out := make([]any, 0, len(lines))
	for i, l := range lines {
		v, err := decodeJSON([]byte(l))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// parseCSV gives one object per row, keyed by the header row. Missing cells are null and rows
// that are completely empty are skipped, as Python's csv.DictReader does.
func parseCSV(text string) ([]any, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1 // rows may be short or long
	r.LazyQuotes = true    // exports often contain stray quotes
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return []any{}, nil
	}
	header := records[0]
	out := []any{}
	for _, rec := range records[1:] {
		if len(rec) == 0 || (len(rec) == 1 && rec[0] == "") {
			continue
		}
		row := map[string]any{}
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			} else {
				row[h] = nil
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// ClassifySyslog: syslog has no "source" field, so decide firewall vs network from content.
// Firewalls log traffic decisions: an action plus addresses. Everything else from a syslog
// device (link up/down, config changes, routing) is treated as network.
func ClassifySyslog(line string) string {
	msg, err := normalize.ParseSyslog(line, time.Now().UTC())
	if err != nil {
		return "network" // unparseable; the network normalizer will report the real error
	}
	switch strings.ToLower(msg.KV["action"]) {
	case "accept", "allow", "permit", "pass", "deny", "drop", "block", "reject":
		for _, k := range []string{"src", "dst", "ip", "srcip", "dstip", "src_ip", "dst_ip"} {
			if _, ok := msg.KV[k]; ok {
				return "firewall"
			}
		}
	}
	return "network"
}

// CheckTSWindow returns why a time can't be stored as-is, or "".
//
// Older than retention: that day would be dropped by the next retention run anyway.
// More than a day in the future: almost always a broken clock or timezone bug.
func CheckTSWindow(ts time.Time, retentionDays int, now time.Time) string {
	if ts.Before(now.AddDate(0, 0, -retentionDays)) {
		return fmt.Sprintf("timestamp %s is older than the %d-day retention window", ts.Format(time.RFC3339), retentionDays)
	}
	if ts.After(now.Add(24 * time.Hour)) {
		return fmt.Sprintf("timestamp %s is more than 1 day in the future", ts.Format(time.RFC3339))
	}
	return ""
}
