from datetime import datetime, timezone

import pytest

from app.normalizers.syslog import parse_syslog, parse_tenant_map, tenant_for_sender

from conftest import NOW


def test_parses_rfc3164_header_and_kv():
    m = parse_syslog('<134>Oct 12 08:15:01 fw01 action=deny src=1.2.3.4 msg="two words"', now=NOW)
    assert m.ts == datetime(2026, 10, 12, 8, 15, 1, tzinfo=timezone.utc)
    assert (m.facility, m.syslog_severity, m.host) == (16, 6, "fw01")
    assert m.kv == {"action": "deny", "src": "1.2.3.4", "msg": "two words"}


@pytest.mark.parametrize("pri,expected", [(0, 10), (1, 9), (2, 8), (3, 7), (4, 5), (5, 3), (6, 2), (7, 0), (134, 2)])
def test_pri_severity_maps_to_0_10(pri, expected):
    assert parse_syslog(f"<{pri}>Oct 12 08:00:00 h x=1", now=NOW).severity == expected


def test_space_padded_day():
    assert parse_syslog("<13>Oct  2 08:00:00 h x=1", now=NOW).ts.day == 2


def test_missing_year_assumes_current_year():
    assert parse_syslog("<13>Mar  1 00:00:00 h x=1", now=NOW).ts.year == 2026


def test_year_rollover_dec_line_received_in_january():
    jan = datetime(2027, 1, 1, 0, 0, 5, tzinfo=timezone.utc)
    assert parse_syslog("<13>Dec 31 23:59:59 h x=1", now=jan).ts == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def test_rfc3339_timestamp_variant():
    m = parse_syslog("<13>1 2026-10-12T08:00:00+02:00 h x=1", now=NOW)
    assert m.ts == datetime(2026, 10, 12, 6, 0, tzinfo=timezone.utc)


def test_program_tag_is_split_off():
    m = parse_syslog("<13>Oct 12 08:00:00 h sshd[42]: Failed password user=root", now=NOW)
    assert m.tag == "sshd" and m.message.startswith("Failed password")


@pytest.mark.parametrize("line", ["no pri here", "<999>Oct 12 08:00:00 h x", ""])
def test_rejects_garbage(line):
    with pytest.raises(ValueError):
        parse_syslog(line, now=NOW)


def test_tenant_by_sender_ip_most_specific_wins():
    tmap = parse_tenant_map("10.0.0.0/8=demoA, 10.0.2.0/24=demoB")
    assert tenant_for_sender("10.0.2.7", tmap, "default") == "demoB"
    assert tenant_for_sender("10.9.9.9", tmap, "default") == "demoA"


@pytest.mark.parametrize("sender", ["192.168.1.1", None, "garbage"])
def test_unknown_sender_gets_default_tenant(sender):
    assert tenant_for_sender(sender, parse_tenant_map("10.0.0.0/8=demoA"), "default") == "default"


def test_tenant_map_rejects_entry_without_tenant():
    with pytest.raises(ValueError):
        parse_tenant_map("10.0.0.0/8")
