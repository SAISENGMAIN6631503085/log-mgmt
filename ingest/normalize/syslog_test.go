package normalize

import (
	"fmt"
	"testing"
)

// Ported from tests/test_normalize_syslog.py (same cases).

func TestParsesRFC3164HeaderAndKV(t *testing.T) {
	m, err := ParseSyslog(`<134>Oct 12 08:15:01 fw01 action=deny src=1.2.3.4 msg="two words"`, NOW)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, m.TS, utc(2026, 10, 12, 8, 15, 1))
	eq(t, joined(m.Facility, m.SyslogSeverity, m.Host), "16 6 fw01")
	eq(t, len(m.KV), 3)
	eq(t, m.KV["action"]+"|"+m.KV["src"]+"|"+m.KV["msg"], "deny|1.2.3.4|two words")
}

func TestPRISeverityMapsTo0To10(t *testing.T) {
	for pri, want := range map[int]int{0: 10, 1: 9, 2: 8, 3: 7, 4: 5, 5: 3, 6: 2, 7: 0, 134: 2} {
		m, err := ParseSyslog(fmt.Sprintf("<%d>Oct 12 08:00:00 h x=1", pri), NOW)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, m.Severity, want)
	}
}

func TestSpacePaddedDay(t *testing.T) {
	m, _ := ParseSyslog("<13>Oct  2 08:00:00 h x=1", NOW)
	eq(t, m.TS.Day(), 2)
}

func TestMissingYearAssumesCurrentYear(t *testing.T) {
	m, _ := ParseSyslog("<13>Mar  1 00:00:00 h x=1", NOW)
	eq(t, m.TS.Year(), 2026)
}

func TestYearRolloverDecLineReceivedInJanuary(t *testing.T) {
	m, _ := ParseSyslog("<13>Dec 31 23:59:59 h x=1", utc(2027, 1, 1, 0, 0, 5))
	eq(t, m.TS, utc(2026, 12, 31, 23, 59, 59))
}

func TestRFC3339TimestampVariant(t *testing.T) {
	m, err := ParseSyslog("<13>1 2026-10-12T08:00:00+02:00 h x=1", NOW)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, m.TS, utc(2026, 10, 12, 6, 0, 0))
}

func TestProgramTagIsSplitOff(t *testing.T) {
	m, _ := ParseSyslog("<13>Oct 12 08:00:00 h sshd[42]: Failed password user=root", NOW)
	eq(t, m.Tag, "sshd")
	eq(t, m.Message[:15], "Failed password")
}

func TestRejectsGarbage(t *testing.T) {
	for _, line := range []string{"no pri here", "<999>Oct 12 08:00:00 h x", ""} {
		if _, err := ParseSyslog(line, NOW); err == nil {
			t.Errorf("%q: want an error", line)
		}
	}
}

func TestTenantBySenderIPMostSpecificWins(t *testing.T) {
	routes, err := ParseTenantMap("10.0.0.0/8=demoA, 10.0.2.0/24=demoB")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, TenantForSender("10.0.2.7", routes, "default"), "demoB")
	eq(t, TenantForSender("10.9.9.9", routes, "default"), "demoA")
}

func TestUnknownSenderGetsDefaultTenant(t *testing.T) {
	routes, _ := ParseTenantMap("10.0.0.0/8=demoA")
	for _, sender := range []string{"192.168.1.1", "", "garbage"} {
		eq(t, TenantForSender(sender, routes, "default"), "default")
	}
}

func TestTenantMapRejectsEntryWithoutTenant(t *testing.T) {
	if _, err := ParseTenantMap("10.0.0.0/8"); err == nil {
		t.Error("want an error")
	}
}
