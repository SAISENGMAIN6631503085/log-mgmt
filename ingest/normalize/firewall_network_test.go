package normalize

import (
	"testing"
)

// Ported from tests/test_normalize_firewall.py and tests/test_normalize_network.py.

func firewallEvents(t *testing.T) []*Event {
	var out []*Event
	for _, l := range sampleLines(t, "firewall.log") {
		out = append(out, must(t, Firewall, l, "demoA", NOW))
	}
	return out
}

func TestFirewallEverySampleNormalizes(t *testing.T) {
	evs := firewallEvents(t)
	eq(t, len(evs), 5)
	for _, e := range evs {
		eq(t, e.Source+"/"+e.Tenant, "firewall/demoA")
	}
}

func TestFirewallDenyEventFieldsAndAliases(t *testing.T) {
	e := firewallEvents(t)[1]
	eq(t, e.TS, utc(2026, 10, 12, 8, 15, 7))
	eq(t, s(e.Vendor)+"|"+s(e.Product)+"|"+s(e.Host), "Fortinet|FortiGate|fw01")
	eq(t, s(e.Action), "deny")
	eq(t, hasTag(e, "blocked"), true)
	eq(t, joined(s(e.SrcIP), i(e.SrcPort), s(e.DstIP), i(e.DstPort), s(e.Protocol)), "203.0.113.45 51234 10.0.0.10 22 tcp")
	eq(t, s(e.RuleID)+"|"+s(e.RuleName), "1001|Block SSH from internet")
	eq(t, i(e.Severity), 5) // PRI 132 -> syslog warning(4) -> 5
}

func TestFirewallVendorVerbsMapToAllowDeny(t *testing.T) {
	var got []string
	for _, e := range firewallEvents(t) {
		got = append(got, s(e.Action))
	}
	eq(t, joined(got), "[allow deny deny allow deny]")
}

func TestFirewallIPAliasMapsToSrcIP(t *testing.T) {
	eq(t, s(firewallEvents(t)[3].SrcIP), "10.0.2.14")
}

func TestFirewallRawKeepsOriginalLine(t *testing.T) {
	line := sampleLines(t, "firewall.log")[0]
	eq(t, must(t, Firewall, line, "demoA", NOW).Raw["message"], any(line))
}

func TestFirewallExplicitEventTypeAndAlertSeverity(t *testing.T) {
	e := firewallEvents(t)[4]
	eq(t, joined(s(e.EventType), s(e.EventSubtype), i(e.Severity)), "threat port_scan 9")
}

func networkEvents(t *testing.T) []*Event {
	var out []*Event
	for _, l := range sampleLines(t, "network.log") {
		out = append(out, must(t, Network, l, "demoB", NOW))
	}
	return out
}

func TestNetworkEverySampleNormalizes(t *testing.T) {
	evs := networkEvents(t)
	eq(t, len(evs), 4)
	for _, e := range evs {
		eq(t, e.Source+"/"+e.Tenant, "network/demoB")
	}
}

func TestNetworkLinkDown(t *testing.T) {
	e := networkEvents(t)[0]
	eq(t, joined(s(e.EventType), s(e.EventSubtype), s(e.Host), s(e.Process)), "link_down Gi1/0/24 core-sw01 %LINK-3-UPDOWN")
	eq(t, i(e.Severity), 7) // PRI 187 -> err(3)
}

func TestNetworkConfigChangeKeepsUserAndSrc(t *testing.T) {
	e := networkEvents(t)[2]
	eq(t, joined(s(e.EventType), s(e.User), s(e.SrcIP)), "config_change netadmin 10.0.9.5")
}

func TestNetworkDstAlias(t *testing.T) {
	eq(t, s(networkEvents(t)[3].DstIP), "192.0.2.1")
}

func TestNetworkEventTypeFallsBackToTag(t *testing.T) {
	e := must(t, Network, "<189>Oct 12 08:00:00 sw %SYS-5-RESTART: System restarted", "t", NOW)
	eq(t, s(e.EventType), "SYS-5-RESTART")
}
