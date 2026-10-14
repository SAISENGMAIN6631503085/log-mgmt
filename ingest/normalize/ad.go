package normalize

import (
	"fmt"
	"strconv"
	"time"
)

// Active Directory / Windows Security events (CSV export rows or JSON) -> Event.

type adEvent struct {
	eventType string
	action    string // "" = none
	severity  int
	tags      []string
}

// Only the event IDs a SOC usually watches.
var adEvents = map[int]adEvent{
	4624: {"logon_success", "login", 2, nil},
	4625: {"logon_failure", "login", 5, []string{AuthFailure}},
	4634: {"logoff", "logout", 1, nil},
	4720: {"user_created", "create", 4, nil},
	4726: {"user_deleted", "delete", 5, nil},
	4740: {"account_lockout", "alert", 6, []string{"account_lockout"}},
}

// adFromFlat reshapes the assignment's flat AD sample ({"event_id": 4625, "user": ..., "ip": ...})
// as an export row.
func adFromFlat(d map[string]any) map[string]any {
	return map[string]any{
		"TimeCreated":    flatTime(d),
		"EventID":        d["event_id"],
		"TargetUserName": d["user"],
		"Computer":       d["host"],
		"IpAddress":      first(d["src_ip"], d["ip"]),
		"IpPort":         d["src_port"],
		"LogonType":      d["logon_type"],
		"_event_type":    d["event_type"],
	}
}

func AD(payload any, tenant string, _ time.Time) (*Event, error) {
	original, err := object(payload)
	if err != nil {
		return nil, err
	}
	row := original
	_, hasID := row["EventID"]
	_, hasTime := row["TimeCreated"]
	if !hasID && !hasTime {
		row = adFromFlat(row)
	}
	id := ToInt(row["EventID"])
	known := adEvent{severity: 2}
	if id != nil {
		if e, ok := adEvents[*id]; ok {
			known = e
		}
	}
	if known.eventType == "" {
		// Unknown IDs keep the sender's own event_type name if it gave one.
		known.eventType = str(row["_event_type"])
		if known.eventType == "" {
			known.eventType = fmt.Sprintf("event_%s", idText(id))
		}
	}
	ts, err := ParseTS(row["TimeCreated"])
	if err != nil {
		return nil, err
	}
	var subtype *string
	if id != nil {
		subtype = ptr(strconv.Itoa(*id))
	}
	return &Event{
		TS: ts, Tenant: tenant, Source: "ad",
		Vendor: ptr("Microsoft"), Product: ptr("Active Directory"),
		EventType: ptr(known.eventType), EventSubtype: subtype,
		Severity: ptr(known.severity), Action: strOrNil(known.action),
		SrcIP: CleanIP(row["IpAddress"]), SrcPort: ToPort(row["IpPort"]),
		User: text(BlankToNil(row["TargetUserName"])), Host: text(BlankToNil(row["Computer"])),
		Raw:  original,
		Tags: append([]string{}, known.tags...), // a copy: events must not share the table's slices
	}, nil
}

func idText(id *int) string {
	if id == nil {
		return "None" // same text as the Python version gave, so stored names stay consistent
	}
	return strconv.Itoa(*id)
}
