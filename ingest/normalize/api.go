package normalize

import (
	"strings"
	"time"
)

// Application/API JSON events (our own HTTP ingest format) -> Event.

// CLAUDE.md: api `*_failed` -> login + auth_failure. Restricted to auth-related names so that
// e.g. "payment_failed" doesn't count toward the brute-force login alert.
var authWords = []string{"login", "logon", "signin", "sign_in", "auth", "mfa", "password"}

func isAuth(eventType string) bool {
	for _, w := range authWords {
		if strings.Contains(eventType, w) {
			return true
		}
	}
	return false
}

func API(payload any, tenant string, now time.Time) (*Event, error) {
	raw, err := object(payload)
	if err != nil {
		return nil, err
	}
	d := UnifyAliases(raw)
	eventType := strings.ToLower(str(first(d["event_type"])))
	status := ToInt(firstPresent(d, "status_code", "status"))

	tags := []string{}
	var action *string
	if a := str(d["action"]); actions[a] {
		action = &a
	}
	if eventType != "" && isAuth(eventType) {
		if action == nil {
			action = ptr("login")
		}
		if strings.HasSuffix(eventType, "_failed") {
			tags = append(tags, AuthFailure)
		}
	} else if strings.HasPrefix(eventType, "logout") && action == nil {
		action = ptr("logout")
	}

	severity := ToInt(d["severity"])
	if severity == nil || *severity < 0 || *severity > 10 {
		// Derive from the outcome when the app didn't send one.
		switch {
		case status != nil && *status >= 500:
			severity = ptr(6)
		case len(tags) > 0:
			severity = ptr(5)
		case status != nil && *status >= 400:
			severity = ptr(4)
		default:
			severity = ptr(2)
		}
	}

	ts := now // apps sometimes omit the time; receipt time is the best we have
	if v := flatTime(d); v != nil {
		if ts, err = ParseTS(v); err != nil {
			return nil, err
		}
	}
	return &Event{
		TS: ts,
		// The tenant comes from the API key, never from the body: a client must not be able to
		// write into another tenant by putting "tenant": "x" in the JSON.
		Tenant: tenant, Source: "api",
		Vendor:       text(first(d["vendor"], "custom")),
		Product:      text(first(d["service"], d["product"])),
		EventType:    strOrNil(eventType),
		EventSubtype: text(first(d["event_subtype"], d["reason"])),
		Severity:     severity, Action: action,
		SrcIP: CleanIP(d["src_ip"]), SrcPort: ToPort(d["src_port"]),
		DstIP: CleanIP(d["dst_ip"]), DstPort: ToPort(d["dst_port"]),
		User:       text(first(d["user"], d["username"])),
		Host:       text(d["host"]),
		Process:    text(d["process"]),
		URL:        text(first(d["url"], d["path"])),
		HTTPMethod: strOrNil(strings.ToUpper(str(first(d["http_method"], d["method"])))),
		StatusCode: status,
		Raw:        raw,
		Tags:       tags,
	}, nil
}

// firstPresent is d[a] if the key exists (even with an empty value), else d[b]: Python's
// d.get(a, d.get(b)).
func firstPresent(d map[string]any, a, b string) any {
	if v, ok := d[a]; ok {
		return v
	}
	return d[b]
}
