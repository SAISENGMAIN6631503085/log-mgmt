package normalize

import (
	"errors"
	"strings"
	"time"
)

// Firewall syslog (FortiGate, PAN-OS, ... in key=value form) -> Event.

// Every vendor has its own verb for allow/deny; the schema only has two.
var firewallActions = map[string]string{
	"accept": "allow", "allow": "allow", "permit": "allow", "pass": "allow",
	"deny": "deny", "drop": "deny", "block": "deny", "reject": "deny",
}

func Firewall(payload any, tenant string, now time.Time) (*Event, error) {
	line, ok := payload.(string)
	if !ok {
		return nil, errors.New("firewall events must be syslog lines (text)")
	}
	msg, err := ParseSyslog(line, now)
	if err != nil {
		return nil, err
	}
	kv := unifyKV(msg.KV)
	var action *string
	if a, ok := firewallActions[strings.ToLower(kv["action"])]; ok {
		action = &a
	}
	tags := []string{}
	if action != nil && *action == "deny" {
		tags = append(tags, "blocked")
	}
	eventType := "traffic"
	if v, ok := kv["event_type"]; ok {
		eventType = v
	}
	return &Event{
		TS: msg.TS, Tenant: tenant, Source: "firewall",
		Vendor: strOrNil(kv["vendor"]), Product: strOrNil(kv["product"]),
		EventType: strOrNil(eventType), EventSubtype: strOrNil(kv["event_subtype"]),
		Severity: ptr(msg.Severity), Action: action,
		SrcIP: CleanIP(kv["src_ip"]), SrcPort: ToPort(kv["src_port"]),
		DstIP: CleanIP(kv["dst_ip"]), DstPort: ToPort(kv["dst_port"]),
		Protocol: strOrNil(strings.ToLower(kv["protocol"])), User: strOrNil(kv["user"]),
		Host:     strOrNil(msg.Host),
		RuleName: strOrNil(firstStr(kv["rule_name"], kv["policy"])), // e.g. policy=Block-DNS
		RuleID:   strOrNil(kv["rule_id"]),
		Raw:      map[string]any{"message": line},
		Tags:     tags,
	}, nil
}

// unifyKV applies the field aliases to syslog key=value pairs.
func unifyKV(kv map[string]string) map[string]string {
	in := make(map[string]any, len(kv))
	for k, v := range kv {
		in[k] = v
	}
	out := map[string]string{}
	for k, v := range UnifyAliases(in) {
		out[k] = v.(string)
	}
	return out
}

// firstStr is the first non-empty string ("a or b").
func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
