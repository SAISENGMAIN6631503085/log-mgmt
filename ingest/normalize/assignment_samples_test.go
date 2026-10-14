package normalize

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The exact sample logs from the assignment PDF (section 4), which reviewers will send.
// Ported from the unit part of tests/test_assignment_samples.py (same cases).

var samplesNow = utc(2025, 8, 21, 0, 0, 0) // the samples' "Aug 20" is in the past

const (
	pdfFW  = "<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS"
	pdfNET = "<190>Aug 20 13:01:02 r1 if=ge-0/0/1 event=link-down mac=aa:bb:cc:dd:ee:ff reason=carrier-loss"
)

func pdfSample(t *testing.T, text string) map[string]any {
	v, ok := decode(t, []byte(text)).(map[string]any)
	if !ok {
		t.Fatal("not an object")
	}
	return v
}

const (
	pdfAPI  = `{"tenant": "demoA", "source": "api", "event_type": "app_login_failed", "user": "alice", "ip": "203.0.113.7", "reason": "wrong_password", "@timestamp": "2025-08-20T07:20:00Z"}`
	pdfCS   = `{"tenant": "demoA", "source": "crowdstrike", "event_type": "malware_detected", "host": "WIN10-01", "process": "powershell.exe", "severity": 8, "sha256": "abc...", "action": "quarantine", "@timestamp": "2025-08-20T08:00:00Z"}`
	pdfAWS  = `{"tenant": "demoB", "source": "aws", "cloud": {"service": "iam", "account_id": "123456789012", "region": "ap-southeast-1"}, "event_type": "CreateUser", "user": "admin", "@timestamp": "2025-08-20T09:10:00Z", "raw": {"eventName": "CreateUser", "requestParameters": {"userName": "temp-user"}}}`
	pdfM365 = `{"tenant": "demoB", "source": "m365", "event_type": "UserLoggedIn", "user": "bob@demo.local", "ip": "198.51.100.23", "status": "Success", "workload": "Exchange", "@timestamp": "2025-08-20T10:05:00Z"}`
	pdfAD   = `{"tenant": "demoA", "source": "ad", "event_id": 4625, "event_type": "LogonFailed", "user": "demo\\eve", "host": "DC01", "ip": "203.0.113.77", "logon_type": 3, "@timestamp": "2025-08-20T11:11:11Z"}`
)

func TestPDF41FirewallSyslog(t *testing.T) {
	e := must(t, Firewall, pdfFW, "demoA", samplesNow)
	eq(t, joined(s(e.Action), s(e.SrcIP), i(e.SrcPort), s(e.DstIP), i(e.DstPort), s(e.Protocol)), "deny 10.0.1.10 5353 8.8.8.8 53 udp")
	eq(t, joined(s(e.Vendor), s(e.Product), s(e.RuleName), s(e.Host)), "demo ngfw Block-DNS fw01")
}

func TestPDF42NetworkSyslog(t *testing.T) {
	e := must(t, Network, pdfNET, "demoA", samplesNow)
	eq(t, joined(s(e.EventType), s(e.EventSubtype), s(e.Host)), "link-down ge-0/0/1 r1")
}

func TestPDF43API(t *testing.T) {
	e := must(t, API, pdfSample(t, pdfAPI), "demoA", samplesNow)
	eq(t, joined(s(e.EventType), s(e.User), s(e.SrcIP), s(e.Action), s(e.EventSubtype)), "app_login_failed alice 203.0.113.7 login wrong_password")
	eq(t, hasTag(e, "auth_failure"), true)
	eq(t, e.TS, utc(2025, 8, 20, 7, 20, 0))
}

func TestPDF44CrowdStrikeFlat(t *testing.T) {
	e := must(t, CrowdStrike, pdfSample(t, pdfCS), "demoA", samplesNow)
	eq(t, joined(s(e.EventType), s(e.Host), s(e.Process), i(e.Severity), s(e.Action)), "malware_detected WIN10-01 powershell.exe 8 quarantine")
	eq(t, hasTag(e, "quarantined") && e.Raw["sha256"] == "abc...", true)
}

func TestPDF45AWSFlat(t *testing.T) {
	sample := pdfSample(t, pdfAWS)
	e := must(t, AWS, sample, "demoB", samplesNow)
	eq(t, joined(s(e.EventType), s(e.Action), s(e.User)), "CreateUser create admin")
	eq(t, joined(s(e.CloudService), s(e.CloudAccountID), s(e.CloudRegion)), "iam 123456789012 ap-southeast-1")
	eq(t, reflect.DeepEqual(e.Raw, sample), true) // the whole original payload is kept
}

func TestPDF46M365Flat(t *testing.T) {
	e := must(t, M365, pdfSample(t, pdfM365), "demoB", samplesNow)
	eq(t, joined(s(e.EventType), s(e.Action), s(e.User), s(e.SrcIP), s(e.CloudService)), "UserLoggedIn login bob@demo.local 198.51.100.23 Exchange")
	eq(t, hasTag(e, "auth_failure"), false)
}

func TestPDF46M365FlatFailedStatusIsAuthFailure(t *testing.T) {
	sample := pdfSample(t, pdfM365)
	sample["status"] = "Failed"
	eq(t, hasTag(must(t, M365, sample, "demoB", samplesNow), "auth_failure"), true)
}

func TestPDF47ADFlat4625(t *testing.T) {
	e := must(t, AD, pdfSample(t, pdfAD), "demoA", samplesNow)
	eq(t, joined(s(e.EventType), s(e.EventSubtype), s(e.Action), s(e.User), s(e.Host), s(e.SrcIP)),
		`logon_failure 4625 login demo\eve DC01 203.0.113.77`)
	eq(t, hasTag(e, "auth_failure"), true)
}

var _ = json.Number("") // json is used by the helpers in this package's tests
