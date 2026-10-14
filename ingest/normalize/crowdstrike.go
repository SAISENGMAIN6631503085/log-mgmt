package normalize

import (
	"strings"
	"time"
)

// CrowdStrike -> Event. Accepts Falcon streaming API events (DetectionSummaryEvent) and the flat
// format used in the assignment ({"event_type": "malware_detected", "host": ..., "severity": 8}).

func crowdstrikeTags(quarantined bool) []string {
	if quarantined {
		return []string{"edr_detection", "quarantined"}
	}
	return []string{"edr_detection"}
}

func crowdstrikeFlat(payload map[string]any, tenant string) (*Event, error) {
	d := UnifyAliases(payload)
	severity := ToInt(d["severity"])
	if severity != nil && (*severity < 0 || *severity > 10) {
		severity = nil
	}
	action := strings.ToLower(str(d["action"]))
	if !actions[action] {
		action = "alert"
	}
	ts, err := ParseTS(flatTime(d))
	if err != nil {
		return nil, err
	}
	return &Event{
		TS: ts, Tenant: tenant, Source: "crowdstrike",
		Vendor:    text(first(d["vendor"], "CrowdStrike")),
		Product:   text(first(d["product"], "Falcon")),
		EventType: text(d["event_type"]), EventSubtype: text(d["event_subtype"]),
		Severity: severity, Action: &action,
		SrcIP: CleanIP(d["src_ip"]), User: text(d["user"]), Host: text(d["host"]),
		Process: text(d["process"]), RuleName: text(d["rule_name"]), RuleID: text(d["rule_id"]),
		Raw:  payload,
		Tags: crowdstrikeTags(action == "quarantine"),
	}, nil
}

func CrowdStrike(payload any, tenant string, _ time.Time) (*Event, error) {
	d, err := object(payload)
	if err != nil {
		return nil, err
	}
	_, hasMeta := d["metadata"]
	_, hasEvent := d["event"]
	if !hasMeta && !hasEvent {
		return crowdstrikeFlat(d, tenant)
	}
	meta, ev := get(d, "metadata"), get(d, "event")
	flags := get(ev, "PatternDispositionFlags")
	description := strings.ToLower(str(ev["PatternDispositionDescription"]))

	// Falcon severity is 1 (info) .. 5 (critical); double it onto our 0-10 scale.
	var severity *int
	if cs := ToInt(ev["Severity"]); cs != nil {
		severity = ptr(min(*cs*2, 10))
	}
	quarantined := truthy(flags["QuarantineFile"]) || strings.Contains(description, "quarantine")
	action := "alert"
	if quarantined {
		action = "quarantine"
	}
	eventType := text(meta["eventType"])
	if eventType != nil && *eventType == "DetectionSummaryEvent" {
		eventType = ptr("detection")
	}
	ts, err := ParseTS(meta["eventCreationTime"]) // epoch milliseconds
	if err != nil {
		return nil, err
	}
	return &Event{
		TS: ts, Tenant: tenant, Source: "crowdstrike",
		Vendor: ptr("CrowdStrike"), Product: ptr("Falcon"),
		EventType: eventType, EventSubtype: text(ev["Tactic"]),
		Severity: severity, Action: &action,
		SrcIP: CleanIP(ev["LocalIP"]), User: text(ev["UserName"]), Host: text(ev["ComputerName"]),
		Process: text(ev["FileName"]), RuleName: text(first(ev["DetectName"], ev["Technique"])),
		RuleID: text(ev["DetectId"]),
		Raw:    d,
		Tags:   crowdstrikeTags(quarantined),
	}, nil
}
