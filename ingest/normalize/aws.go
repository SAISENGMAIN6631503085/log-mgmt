package normalize

import (
	"errors"
	"strings"
	"time"
)

// AWS CloudTrail records -> Event.

var (
	awsCreate = []string{"Create", "Run", "Put", "Add", "Attach", "Start"}
	awsDelete = []string{"Delete", "Terminate", "Remove", "Detach"}
)

// IterRecords: CloudTrail files wrap events as {"Records": [...]}; a bare list or one record
// also works.
func IterRecords(doc any) ([]any, error) {
	switch x := doc.(type) {
	case map[string]any:
		if recs, ok := x["Records"]; ok {
			list, ok := recs.([]any)
			if !ok {
				return nil, errors.New(`"Records" must be a list`)
			}
			return list, nil
		}
		return []any{x}, nil
	case []any:
		return x, nil
	}
	return []any{doc}, nil
}

// awsFromFlat reshapes the assignment's flat AWS sample as a CloudTrail record, so one mapping
// serves both.
func awsFromFlat(d map[string]any) map[string]any {
	service, account, region := flatCloud(d)
	status := strings.ToLower(str(d["status"]))
	rec := map[string]any{
		"eventTime":          flatTime(d),
		"eventName":          first(d["event_type"], get(d, "raw")["eventName"], ""),
		"awsRegion":          region,
		"recipientAccountId": account,
		"sourceIPAddress":    first(d["src_ip"], d["ip"]),
		"userIdentity":       map[string]any{},
	}
	if truthy(service) {
		rec["eventSource"] = str(service) + ".amazonaws.com"
	}
	if truthy(d["user"]) {
		rec["userIdentity"] = map[string]any{"userName": d["user"]}
	}
	if rec["eventName"] == "ConsoleLogin" && status != "" {
		result := "Success"
		if status == "failure" || status == "failed" {
			result = "Failure"
		}
		rec["responseElements"] = map[string]any{"ConsoleLogin": result}
	}
	if truthy(d["error_code"]) {
		rec["errorCode"] = d["error_code"]
	}
	return rec
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func AWS(payload any, tenant string, _ time.Time) (*Event, error) {
	original, err := object(payload)
	if err != nil {
		return nil, err
	}
	record := original
	_, hasName := record["eventName"]
	_, hasTime := record["eventTime"]
	if !hasName && !hasTime {
		record = awsFromFlat(record)
	}
	name := str(record["eventName"])
	identity := get(record, "userIdentity")
	tags := []string{}
	var action *string
	severity := 2

	switch {
	case name == "ConsoleLogin":
		action = ptr("login")
		if str(get(record, "responseElements")["ConsoleLogin"]) == "Failure" {
			tags = append(tags, AuthFailure)
			severity = 5
		}
	case hasAnyPrefix(name, awsCreate):
		action = ptr("create")
	case hasAnyPrefix(name, awsDelete):
		action, severity = ptr("delete"), 4
	}

	errorCode := str(record["errorCode"])
	if errorCode == "AccessDenied" || errorCode == "UnauthorizedOperation" || strings.HasSuffix(errorCode, "AccessDenied") {
		action, severity = ptr("deny"), max(severity, 5)
		tags = append(tags, "access_denied")
	}

	// Root account use is a classic CloudTrail red flag.
	if str(identity["type"]) == "Root" {
		tags = append(tags, "root_activity")
		severity = max(severity, 7)
	}

	// IAM users have userName; roles only have an ARN (".../role-name"), and the root ARN ends
	// in ":root" with no slash, so take the last segment after either separator.
	arn := str(identity["arn"])
	last := arn[strings.LastIndex(arn, "/")+1:]
	last = last[strings.LastIndex(last, ":")+1:]
	user := text(first(identity["userName"], last))
	if str(identity["type"]) == "AWSService" {
		user = text(identity["invokedBy"])
	}

	ts, err := ParseTS(record["eventTime"])
	if err != nil {
		return nil, err
	}
	sourceIP := record["sourceIPAddress"]
	var host *string
	if CleanIP(sourceIP) == nil {
		// For service-originated calls this is a hostname like "ec2.amazonaws.com", not an IP.
		host = text(sourceIP)
	}
	service, _, _ := strings.Cut(str(record["eventSource"]), ".")
	return &Event{
		TS: ts, Tenant: tenant, Source: "aws",
		Vendor: ptr("AWS"), Product: ptr("CloudTrail"),
		EventType: strOrNil(name), EventSubtype: text(record["errorCode"]),
		Severity: ptr(severity), Action: action,
		SrcIP: CleanIP(sourceIP), User: user, Host: host,
		CloudAccountID: text(first(record["recipientAccountId"], identity["accountId"])),
		CloudRegion:    text(record["awsRegion"]),
		CloudService:   strOrNil(service),
		Raw:            original,
		Tags:           tags,
	}, nil
}
