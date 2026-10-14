package normalize

import (
	"strings"
	"time"
)

// Microsoft 365 Management Activity API audit records -> Event.

// m365FromFlat reshapes the assignment's flat M365 sample as a Management Activity record.
func m365FromFlat(d map[string]any) map[string]any {
	return map[string]any{
		"CreationTime":   flatTime(d),
		"Operation":      first(d["event_type"], ""),
		"UserId":         d["user"],
		"ClientIP":       first(d["src_ip"], d["ip"]),
		"ResultStatus":   d["status"],
		"Workload":       d["workload"],
		"LogonError":     d["reason"],
		"OrganizationId": d["organization_id"],
	}
}

func M365(payload any, tenant string, _ time.Time) (*Event, error) {
	original, err := object(payload)
	if err != nil {
		return nil, err
	}
	record := original
	_, hasOp := record["Operation"]
	_, hasTime := record["CreationTime"]
	if !hasOp && !hasTime {
		record = m365FromFlat(record)
	}
	op := str(record["Operation"])
	status := strings.ToLower(str(record["ResultStatus"]))
	failed := status == "failed" || status == "failure" || op == "UserLoginFailed"
	tags := []string{}
	severity := 2
	var action *string

	switch {
	case op == "UserLoggedIn" || op == "UserLoginFailed" || (failed && str(record["Workload"]) == "AzureActiveDirectory"):
		action = ptr("login")
		if failed {
			tags = append(tags, AuthFailure)
			severity = 5
		}
	case hasAnyPrefix(op, []string{"New-", "Add", "Set-"}) || hasAnySuffix(op, []string{"Created", "Uploaded", "Added"}):
		action = ptr("create")
	case hasAnyPrefix(op, []string{"Remove-", "Delete"}) || hasAnySuffix(op, []string{"Deleted", "Removed"}):
		action, severity = ptr("delete"), 4
	}

	// Mail forwarding to an outside address is a common account-takeover step.
	if op == "New-InboxRule" || op == "Set-InboxRule" {
		params, _ := record["Parameters"].([]any)
		for _, p := range params {
			pm, _ := p.(map[string]any)
			if name := str(pm["Name"]); name == "ForwardTo" || name == "RedirectTo" {
				tags = append(tags, "mail_forwarding_rule")
				severity = max(severity, 6)
				break
			}
		}
	}

	ts, err := ParseTS(record["CreationTime"]) // no zone in the API; documented as UTC
	if err != nil {
		return nil, err
	}
	var url *string
	if u := str(record["ObjectId"]); strings.HasPrefix(u, "http") {
		url = &u
	}
	return &Event{
		TS: ts, Tenant: tenant, Source: "m365",
		Vendor: ptr("Microsoft"), Product: ptr("Microsoft 365"),
		EventType: strOrNil(op), EventSubtype: text(record["LogonError"]),
		Severity: ptr(severity), Action: action,
		SrcIP: CleanIP(record["ClientIP"]), // Exchange sends "ip:port"; CleanIP strips it
		User:  text(record["UserId"]), URL: url,
		CloudAccountID: text(record["OrganizationId"]), CloudService: text(record["Workload"]),
		Raw:  original,
		Tags: tags,
	}, nil
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}
