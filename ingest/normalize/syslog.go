package normalize

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Syslog line parsing shared by the firewall and network normalizers.
//
// Supported: RFC 3164 (`<PRI>Mmm dd hh:mm:ss host msg`) and the common variant with an RFC 3339
// timestamp (`<PRI>[1 ]2026-10-12T08:15:01Z host msg`). The message body is then scanned for
// key=value pairs, which is how most firewalls emit fields.
var (
	syslogHeader = regexp.MustCompile(`(?s)^<(?P<pri>\d{1,3})>` +
		`(?:1 )?` + // RFC 5424 version digit, if present
		`(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)` +
		` (?P<host>\S+) ?(?P<msg>.*)$`)
	// Program tag before the message: "sshd[123]: ..." or Cisco "%LINK-3-UPDOWN: ..."
	syslogTag = regexp.MustCompile(`^(%?[\w./-]+)(?:\[\d+\])?: `)
	// key=value or key="value with spaces"
	syslogKV = regexp.MustCompile(`([A-Za-z_][\w.-]*)=(?:"([^"]*)"|([^\s"]*))`)
)

// syslogToSeverity maps syslog severity 0 (emergency) .. 7 (debug) onto our 0..10 (10 = worst).
var syslogToSeverity = [8]int{10, 9, 8, 7, 5, 3, 2, 0}

type SyslogMessage struct {
	TS             time.Time
	Facility       int
	SyslogSeverity int // raw 0-7
	Severity       int // mapped 0-10
	Host           string
	Tag            string // "" if none
	Message        string
	KV             map[string]string
}

// parseBSDTimestamp: RFC 3164 timestamps have no year or zone, so assume UTC and the current
// year. Year rollover: a "Dec 31 23:59:59" line received on Jan 1 would land a year in the
// future, so anything more than a day ahead of now is moved to the previous year.
func parseBSDTimestamp(s string, now time.Time) (time.Time, error) {
	s = strings.Join(strings.Fields(s), " ") // "Oct  2" (space-padded day) -> "Oct 2"
	t, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", now.Year(), s))
	if err != nil {
		return t, err
	}
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}

func ParseSyslog(line string, now time.Time) (*SyslogMessage, error) {
	m := syslogHeader.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		short := line
		if len(short) > 80 {
			short = short[:80]
		}
		return nil, fmt.Errorf("not a syslog line: %q", short)
	}
	pri, _ := strconv.Atoi(m[1])
	if pri > 191 { // facility max 23 * 8 + severity 7
		return nil, fmt.Errorf("invalid syslog PRI %d", pri)
	}
	var ts time.Time
	var err error
	if tsText := m[2]; tsText[0] >= '0' && tsText[0] <= '9' {
		ts, err = ParseTS(tsText)
	} else {
		ts, err = parseBSDTimestamp(tsText, now)
	}
	if err != nil {
		return nil, err
	}
	msg, tag := m[4], ""
	if t := syslogTag.FindStringSubmatchIndex(msg); t != nil {
		tag, msg = msg[t[2]:t[3]], msg[t[1]:]
	}
	kv := map[string]string{}
	for _, p := range syslogKV.FindAllStringSubmatch(msg, -1) {
		if p[2] != "" || strings.Contains(p[0], `="`) {
			kv[p[1]] = p[2] // quoted value
		} else {
			kv[p[1]] = p[3]
		}
	}
	return &SyslogMessage{
		TS: ts, Facility: pri / 8, SyslogSeverity: pri % 8, Severity: syslogToSeverity[pri%8],
		Host: m[3], Tag: tag, Message: msg, KV: kv,
	}, nil
}

// TenantRoute is one SYSLOG_TENANT_MAP entry: senders in Network belong to Tenant.
type TenantRoute struct {
	Network netip.Prefix
	Tenant  string
}

// ParseTenantMap reads SYSLOG_TENANT_MAP, e.g. "10.0.1.0/24=demoA,10.0.2.5=demoB".
func ParseTenantMap(spec string) ([]TenantRoute, error) {
	var out []TenantRoute
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		network, tenant, ok := strings.Cut(item, "=")
		tenant = strings.TrimSpace(tenant)
		if !ok || tenant == "" {
			return nil, fmt.Errorf("SYSLOG_TENANT_MAP entry needs '=tenant': %q", item)
		}
		network = strings.TrimSpace(network)
		var p netip.Prefix
		var err error
		if strings.Contains(network, "/") {
			p, err = netip.ParsePrefix(network)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(network); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("SYSLOG_TENANT_MAP: %q is not an IP or network", network)
		}
		out = append(out, TenantRoute{Network: p.Masked(), Tenant: tenant})
	}
	return out, nil
}

// TenantForSender: syslog carries no tenant, so it's decided by which device sent it. The most
// specific matching network wins; unknown senders go to the default tenant.
func TenantForSender(sender string, routes []TenantRoute, fallback string) string {
	ip, err := netip.ParseAddr(sender)
	if err != nil {
		return fallback
	}
	best, bestBits := fallback, -1
	for _, r := range routes {
		if r.Network.Contains(ip) && (r.Network.Bits() > bestBits ||
			(r.Network.Bits() == bestBits && r.Tenant > best)) {
			best, bestBits = r.Tenant, r.Network.Bits()
		}
	}
	return best
}
