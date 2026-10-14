package normalize

import (
	"errors"
	"strings"
	"time"
)

// Network device syslog (switches, routers) -> Event.
func Network(payload any, tenant string, now time.Time) (*Event, error) {
	line, ok := payload.(string)
	if !ok {
		return nil, errors.New("network events must be syslog lines (text)")
	}
	msg, err := ParseSyslog(line, now)
	if err != nil {
		return nil, err
	}
	kv := unifyKV(msg.KV)
	// event_type=/event= (Juniper-style "event=link-down"), else the program tag
	// (Cisco "%LINK-3-UPDOWN"), else "system".
	eventType := firstStr(kv["event_type"], kv["event"], strings.TrimLeft(msg.Tag, "%"), "system")
	return &Event{
		TS: msg.TS, Tenant: tenant, Source: "network",
		Vendor: strOrNil(kv["vendor"]), Product: strOrNil(kv["product"]),
		EventType:    strOrNil(eventType),
		EventSubtype: strOrNil(firstStr(kv["interface"], kv["if"], kv["reason"])),
		Severity:     ptr(msg.Severity),
		SrcIP:        CleanIP(kv["src_ip"]), SrcPort: ToPort(kv["src_port"]),
		DstIP: CleanIP(kv["dst_ip"]), DstPort: ToPort(kv["dst_port"]),
		Protocol: strOrNil(strings.ToLower(kv["protocol"])), User: strOrNil(kv["user"]),
		Host: strOrNil(msg.Host), Process: strOrNil(msg.Tag),
		Raw:  map[string]any{"message": line},
		Tags: []string{},
	}, nil
}
