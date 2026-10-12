from app.normalizers import network

from conftest import NOW, sample_lines


def events():
    return [network.normalize(l, "demoB", now=NOW) for l in sample_lines("network.log")]


def test_every_sample_normalizes():
    evs = events()
    assert len(evs) == 4
    assert all(e.source == "network" and e.tenant == "demoB" for e in evs)


def test_link_down():
    e = events()[0]
    assert (e.event_type, e.event_subtype, e.host, e.process) == ("link_down", "Gi1/0/24", "core-sw01", "%LINK-3-UPDOWN")
    assert e.severity == 7  # PRI 187 -> err(3)


def test_config_change_keeps_user_and_src():
    e = events()[2]
    assert (e.event_type, e.user, e.src_ip) == ("config_change", "netadmin", "10.0.9.5")


def test_dst_alias():
    assert events()[3].dst_ip == "192.0.2.1"


def test_event_type_falls_back_to_tag():
    e = network.normalize("<189>Oct 12 08:00:00 sw %SYS-5-RESTART: System restarted", "t", now=NOW)
    assert e.event_type == "SYS-5-RESTART"
