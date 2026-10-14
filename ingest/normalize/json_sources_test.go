package normalize

import (
	"encoding/json"
	"testing"
)

// Ported from tests/test_normalize_{api,aws,crowdstrike,m365,ad}.py (same cases).

func list(t *testing.T, v any) []any {
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("not a list: %T", v)
	}
	return l
}

// --- api ---

func apiEvents(t *testing.T) []*Event {
	var out []*Event
	for _, p := range list(t, sampleJSON(t, "api_events.json")) {
		out = append(out, must(t, API, p, "demoA", NOW))
	}
	return out
}

func TestAPIEverySampleNormalizes(t *testing.T) { eq(t, len(apiEvents(t)), 5) }

func TestAPILoginFailedIsAuthFailure(t *testing.T) {
	e := apiEvents(t)[1]
	eq(t, s(e.Action), "login")
	eq(t, hasTag(e, "auth_failure"), true)
	eq(t, joined(s(e.SrcIP), s(e.User), s(e.HTTPMethod), s(e.URL), i(e.StatusCode)), "203.0.113.77 alice POST /api/v1/login 401")
	eq(t, s(e.EventSubtype), "bad_password")
	eq(t, i(e.Severity), 5)
}

func TestAPINonAuthFailureIsNotTaggedAuthFailure(t *testing.T) {
	e := apiEvents(t)[2] // payment_failed
	eq(t, e.Action == nil && len(e.Tags) == 0, true)
	eq(t, i(e.Severity), 6) // 502
}

func TestAPILoginSuccessAndLogout(t *testing.T) {
	evs := apiEvents(t)
	eq(t, s(evs[0].Action), "login")
	eq(t, len(evs[0].Tags), 0)
	eq(t, s(evs[4].Action), "logout")
}

func TestAPITenantInBodyIsIgnored(t *testing.T) {
	e := must(t, API, map[string]any{"timestamp": "2026-10-12T08:00:00Z", "tenant": "demoB", "event_type": "x"}, "demoA", NOW)
	eq(t, e.Tenant, "demoA")
	eq(t, e.Raw["tenant"], any("demoB")) // still visible in the original payload
}

func TestAPIMissingTimestampUsesReceiptTime(t *testing.T) {
	eq(t, must(t, API, map[string]any{"event_type": "x"}, "t", NOW).TS, NOW)
}

func TestAPIExplicitSeverityIsKeptAndBadOneIsDerived(t *testing.T) {
	ts := "2026-10-12T08:00:00Z"
	eq(t, i(must(t, API, map[string]any{"timestamp": ts, "severity": json.Number("9")}, "t", NOW).Severity), 9)
	eq(t, i(must(t, API, map[string]any{"timestamp": ts, "severity": json.Number("99")}, "t", NOW).Severity), 2)
}

func TestAPITimestampParsedAsUTC(t *testing.T) {
	eq(t, apiEvents(t)[0].TS, utc(2026, 10, 12, 8, 0, 0))
}

// --- aws ---

func awsEvents(t *testing.T) []*Event {
	recs, err := IterRecords(sampleJSON(t, "aws_cloudtrail.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []*Event
	for _, r := range recs {
		out = append(out, must(t, AWS, r, "demoA", NOW))
	}
	return out
}

func TestAWSEveryRecordNormalizes(t *testing.T) { eq(t, len(awsEvents(t)), 6) }

func TestAWSFailedConsoleLogin(t *testing.T) {
	e := awsEvents(t)[0]
	eq(t, joined(s(e.EventType), s(e.Action), s(e.User), s(e.SrcIP)), "ConsoleLogin login carol 203.0.113.99")
	eq(t, hasTag(e, "auth_failure") && i(e.Severity) == 5, true)
	eq(t, joined(s(e.CloudAccountID), s(e.CloudRegion), s(e.CloudService)), "123456789012 us-east-1 signin")
}

func TestAWSRootLoginIsFlagged(t *testing.T) {
	e := awsEvents(t)[1]
	eq(t, joined(e.Tags, i(e.Severity), s(e.User)), "[root_activity] 7 root")
}

func TestAWSCreateAndDeleteActions(t *testing.T) {
	evs := awsEvents(t)
	eq(t, joined(s(evs[2].Action), s(evs[2].CloudService), s(evs[2].CloudRegion)), "create ec2 eu-west-1")
	eq(t, joined(s(evs[3].Action), i(evs[3].Severity)), "delete 4")
}

func TestAWSAccessDeniedOverridesAction(t *testing.T) {
	e := awsEvents(t)[4]
	eq(t, s(e.Action), "deny")
	eq(t, hasTag(e, "access_denied"), true)
	eq(t, s(e.EventSubtype), "AccessDenied")
}

func TestAWSServiceCallerHostnameIsNotAnIP(t *testing.T) {
	e := awsEvents(t)[5]
	eq(t, joined(s(e.SrcIP), s(e.Host), s(e.User)), "<nil> events.amazonaws.com events.amazonaws.com")
}

func TestAWSIterRecordsAcceptsListAndSingle(t *testing.T) {
	two, _ := IterRecords([]any{map[string]any{}, map[string]any{}})
	one, _ := IterRecords(map[string]any{"eventName": "x"})
	eq(t, len(two), 2)
	eq(t, len(one), 1)
}

// --- crowdstrike ---

func csEvents(t *testing.T) []*Event {
	var out []*Event
	for _, p := range sampleNDJSON(t, "crowdstrike_detections.ndjson") {
		out = append(out, must(t, CrowdStrike, p, "demoA", NOW))
	}
	return out
}

func TestCrowdStrikeEverySampleNormalizes(t *testing.T) { eq(t, len(csEvents(t)), 2) }

func TestCrowdStrikeQuarantinedDetection(t *testing.T) {
	e := csEvents(t)[0]
	eq(t, e.TS, utc(2026, 10, 12, 8, 0, 0)) // from epoch ms
	eq(t, s(e.Vendor)+"|"+s(e.Product)+"|"+s(e.EventType)+"|"+s(e.EventSubtype), "CrowdStrike|Falcon|detection|Credential Access")
	eq(t, joined(s(e.Host), s(e.User), s(e.Process), s(e.SrcIP)), "WS-042 bob mimikatz.exe 10.0.1.42")
	eq(t, s(e.RuleName)+"|"+s(e.RuleID), "Mimikatz credential theft|ldt:a1b2c3:1001")
	eq(t, s(e.Action) == "quarantine" && hasTag(e, "quarantined"), true)
	eq(t, i(e.Severity), 10) // Falcon 5 -> 10
}

func TestCrowdStrikeDetectionWithoutQuarantineIsAlert(t *testing.T) {
	e := csEvents(t)[1]
	eq(t, s(e.Action), "alert")
	eq(t, i(e.Severity), 6)
	eq(t, hasTag(e, "quarantined"), false)
}

// --- m365 ---

func m365Events(t *testing.T) []*Event {
	var out []*Event
	for _, r := range list(t, sampleJSON(t, "m365_audit.json")) {
		out = append(out, must(t, M365, r, "demoB", NOW))
	}
	return out
}

func TestM365EverySampleNormalizes(t *testing.T) { eq(t, len(m365Events(t)), 4) }

func TestM365SuccessfulLogin(t *testing.T) {
	e := m365Events(t)[0]
	eq(t, joined(s(e.Action), e.Tags, s(e.User)), "login [] erin@contoso.com")
	eq(t, e.TS, utc(2026, 10, 12, 9, 0, 0)) // zone-less -> UTC
}

func TestM365FailedLoginIsAuthFailure(t *testing.T) {
	e := m365Events(t)[1]
	eq(t, joined(s(e.Action), s(e.EventSubtype), s(e.SrcIP)), "login InvalidPassword 203.0.113.120")
	eq(t, hasTag(e, "auth_failure"), true)
}

func TestM365FailedStatusAloneCountsAsFailedLogin(t *testing.T) {
	e := must(t, M365, map[string]any{"CreationTime": "2026-10-12T09:00:00", "Operation": "UserLoggedIn",
		"ResultStatus": "Failed", "Workload": "AzureActiveDirectory"}, "t", NOW)
	eq(t, s(e.Action) == "login" && hasTag(e, "auth_failure"), true)
}

func TestM365FileDeleted(t *testing.T) {
	e := m365Events(t)[2]
	eq(t, s(e.Action)+"|"+s(e.CloudService), "delete|SharePoint")
	eq(t, s(e.URL)[len(s(e.URL))-len("salaries.xlsx"):], "salaries.xlsx")
}

func TestM365ForwardingInboxRuleAndIPWithPort(t *testing.T) {
	e := m365Events(t)[3]
	eq(t, s(e.Action) == "create" && hasTag(e, "mail_forwarding_rule") && i(e.Severity) == 6, true)
	eq(t, s(e.SrcIP), "203.0.113.120")
}

// --- ad ---

func adEventsSample(t *testing.T) []*Event {
	var out []*Event
	for _, r := range sampleCSV(t, "ad_security.csv") {
		out = append(out, must(t, AD, r, "demoA", NOW))
	}
	return out
}

func TestADEveryRowNormalizes(t *testing.T) { eq(t, len(adEventsSample(t)), 11) }

func TestAD4625IsFailedLogin(t *testing.T) {
	e := adEventsSample(t)[1]
	eq(t, joined(s(e.EventType), s(e.EventSubtype), s(e.Action)), "logon_failure 4625 login")
	eq(t, hasTag(e, "auth_failure"), true)
	eq(t, joined(s(e.User), s(e.SrcIP), i(e.SrcPort), s(e.Host)), "administrator 203.0.113.50 51001 DC01.corp.local")
}

func TestADSampleContainsBruteForceBurst(t *testing.T) {
	// The alert rule needs >= 5 failures from one IP within 5 minutes; the sample provides 6.
	var fails []*Event
	for _, e := range adEventsSample(t) {
		if hasTag(e, "auth_failure") && s(e.SrcIP) == "203.0.113.50" {
			fails = append(fails, e)
		}
	}
	eq(t, len(fails), 6)
	eq(t, fails[len(fails)-1].TS.Sub(fails[0].TS).Seconds() <= 300, true)
}

func TestADOtherEventIDs(t *testing.T) {
	byID := map[string]*Event{}
	for _, e := range adEventsSample(t) {
		byID[s(e.EventSubtype)] = e
	}
	eq(t, s(byID["4624"].Action) == "login" && len(byID["4624"].Tags) == 0, true)
	eq(t, s(byID["4634"].Action), "logout")
	eq(t, s(byID["4720"].Action), "create")
	eq(t, s(byID["4726"].Action), "delete")
	eq(t, s(byID["4740"].Action) == "alert" && hasTag(byID["4740"], "account_lockout"), true)
}

func TestADDashPlaceholdersBecomeNil(t *testing.T) {
	e := adEventsSample(t)[7] // 4740: IpAddress and IpPort are "-"
	eq(t, e.SrcIP == nil && e.SrcPort == nil, true)
}

func TestADUnknownEventIDStillNormalizes(t *testing.T) {
	e := must(t, AD, map[string]any{"TimeCreated": "2026-10-12T10:00:00Z", "EventID": "4688"}, "t", NOW)
	eq(t, s(e.EventType)+"|"+s(e.Action), "event_4688|<nil>")
}

func TestADTagsAreNotSharedBetweenEvents(t *testing.T) {
	evs := adEventsSample(t)
	a, b := evs[1], evs[2]
	a.Tags = append(a.Tags, "x")
	eq(t, hasTag(b, "x"), false)
}
