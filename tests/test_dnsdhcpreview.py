import csv
import ipaddress
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dnsdhcpreview import simulate
from dnsdhcpreview.checks import RED, review, reverse_net, summary
from dnsdhcpreview.cli import OUTPUTS, run
from dnsdhcpreview.model import duration, host, load, mac, network, purpose, updates

AS_OF = "2026-11-14 09:00"


def write(path: Path, head: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(head)
        w.writerows(rows)


def estate(tmp_path: Path, **over) -> Path:
    """A small estate: two servers in failover, one scope each way, a clean zone. Keyword args replace whole files."""
    files = {
        "dhcp-scopes.csv": (["Server", "ScopeId", "SubnetMask", "Name", "StartRange", "EndRange", "State", "LeaseDuration", "InUse",
                             "Free", "FailoverRelationship"],
                            [["DC1", "10.1.10.0", "255.255.255.0", "Users", "10.1.10.20", "10.1.10.219", "Active", "8.00:00:00", 100,
                              100, "DC1-DC2"]]),
        "dhcp-options.csv": (["Server", "ScopeId", "OptionId", "Value"],
                             [["DC1", "10.1.10.0", 6, "10.1.0.11,10.1.0.12"], ["DC1", "10.1.10.0", 3, "10.1.10.1"]]),
        "dhcp-failover.csv": (["Name", "Server", "PartnerServer", "Mode", "State", "ScopeId"],
                              [["DC1-DC2", "DC1", "DC2", "LoadBalance", "Normal", "10.1.10.0"]]),
        "dhcp-servers.csv": (["DnsName", "IPAddress", "Authorized", "Source"],
                             [["dc1.corp.test", "10.1.0.11", "True", "AD"], ["dc2.corp.test", "10.1.0.12", "True", "AD"]]),
        "dns-servers.csv": (["Server", "IPAddress", "ScavengingState", "Forwarders", "Status"],
                            [["DC1", "10.1.0.11", "True", "10.0.0.53", ""], ["DC2", "10.1.0.12", "False", "10.0.0.53", ""]]),
        "dns-zones.csv": (["ZoneName", "IsDsIntegrated", "DynamicUpdate", "IsReverseLookupZone", "AgingEnabled", "NoRefreshInterval",
                           "RefreshInterval"],
                          [["corp.test", "True", "Secure", "False", "True", "7.00:00:00", "7.00:00:00"],
                           ["1.10.in-addr.arpa", "True", "Secure", "True", "True", "7.00:00:00", "7.00:00:00"]]),
        "dns-records.csv": (["ZoneName", "HostName", "RecordType", "RecordData", "Timestamp"],
                            [["corp.test", "dc1", "A", "10.1.0.11", "0"], ["1.10.in-addr.arpa", "11.0", "PTR", "dc1.corp.test", "0"],
                             ["corp.test", "pc1", "A", "10.1.10.25", "2026-11-12 08:00:00"]]),
        "ip-plan.csv": (["Subnet", "Site", "Vlan", "Purpose", "Owner", "Dhcp"],
                        [["10.1.0.0/24", "HQ", 10, "servers", "Server team", "no"], ["10.1.10.0/24", "HQ", 110, "users", "Network", "yes"]]),
    }
    for k, v in over.items():
        files[k.replace("_", "-") + ".csv"] = v
    for name, (head, rows) in files.items():
        if rows is not None:
            write(tmp_path / name, head, rows)
    (tmp_path / "settings.json").write_text(json.dumps({"organisation": "Test", "review_date": AS_OF, "approved_forwarders": ["10.0.0.53"]}))
    return tmp_path


def codes(rv) -> dict:
    out = {}
    for f in rv["findings"]:
        out.setdefault(f.code, []).append(f)
    return out


def test_parsers():
    assert mac("00:15:5D:0A:01:FF") == "00-15-5d-0a-01-ff" == mac("00155d0a01ff")
    assert duration("8.00:00:00") == timedelta(days=8) and duration("04:00:00") == timedelta(hours=4)
    assert duration("1d") == timedelta(days=1) and duration("90") == timedelta(minutes=90)
    assert network("10.1.10.0", "255.255.254.0") == ipaddress.IPv4Network("10.1.10.0/23")
    assert updates("NonsecureAndSecure") == "nonsecure" and updates("Secure") == "secure" and updates("None") == "none"
    assert purpose("MAD Guest Wi-Fi") == "guest" and purpose("Corporate Wi-Fi") == "wifi" and purpose("Handheld scanners") == "scanners"
    assert purpose("Meeting rooms AV") == "av" and purpose("Floor 3 users") == "users" and purpose("Label printers") == "printers"
    assert reverse_net("20.10.in-addr.arpa") == ipaddress.IPv4Network("10.20.0.0/16")
    assert host("mad-dc01.corp.example.") == "MAD-DC01"


def test_clean_estate_has_no_findings(tmp_path):
    d = load(estate(tmp_path))
    rv = review(d)
    assert rv["findings"] == [], [f.code for f in rv["findings"]]
    assert summary(d, rv)["status"] == "GREEN" and summary(d, rv)["failover_pct"] == 100


def test_loads_other_column_names(tmp_path):
    estate(tmp_path, dhcp_scopes=(["ComputerName", "Subnet", "Mask", "Scope name", "Start", "End", "Status", "Lease", "Used", "Available",
                                   "Relationship"],
                                  [["dc1.corp.test", "10.1.10.0", "255.255.255.0", "Users", "10.1.10.20", "10.1.10.219", "Active", "8d",
                                    "150", "50", "DC1-DC2"]]))
    d = load(tmp_path)
    sc = d.scopes[0]
    assert sc.server == "DC1" and sc.net.prefixlen == 24 and sc.pct == 75 and sc.lease == timedelta(days=8)
    assert d.sources["dhcp-scopes.csv"] == 1


def test_utilisation_and_forecast(tmp_path):
    estate(tmp_path, dhcp_scopes=(["Server", "ScopeId", "SubnetMask", "Name", "StartRange", "EndRange", "LeaseDuration", "InUse", "Free",
                                   "FailoverRelationship"],
                                  [["DC1", "10.1.10.0", "255.255.255.0", "Users", "10.1.10.20", "10.1.10.219", "8.00:00:00", 185, 15, "DC1-DC2"],
                                   ["DC1", "10.1.20.0", "255.255.255.0", "Floor 2 users", "10.1.20.20", "10.1.20.219", "8.00:00:00", 120, 80, "DC1-DC2"]]),
           dhcp_failover=(["Name", "Server", "PartnerServer", "Mode", "State", "ScopeId"],
                          [["DC1-DC2", "DC1", "DC2", "LoadBalance", "Normal", "10.1.10.0;10.1.20.0"]]),
           previous_scopes=(["server", "scope", "in_use"], [["DC1", "10.1.10.0", 180], ["DC1", "10.1.20.0", 60]]))
    s = json.loads((tmp_path / "settings.json").read_text())
    s["previous_review"] = "2026-10-14"
    (tmp_path / "settings.json").write_text(json.dumps(s))
    c = codes(review(load(tmp_path)))
    assert c["DHCP-FULL"][0].severity == RED and "92 %" in c["DHCP-FULL"][0].detail
    assert "DHCP-FORECAST" not in c                  # +60 in 31 days, 80 free: about 41 days, outside the 30-day window
    s["forecast_days"] = 45
    (tmp_path / "settings.json").write_text(json.dumps(s))
    c = codes(review(load(tmp_path)))
    assert "Floor 2 users" in c["DHCP-FORECAST"][0].subject and "full in about 41 days" in c["DHCP-FORECAST"][0].detail


def test_failover_options_overlap_and_rogue(tmp_path):
    estate(tmp_path,
           dhcp_scopes=(["Server", "ScopeId", "SubnetMask", "Name", "StartRange", "EndRange", "LeaseDuration", "InUse", "Free", "FailoverRelationship"],
                        [["DC1", "10.1.10.0", "255.255.255.0", "Users", "10.1.10.20", "10.1.10.219", "8.00:00:00", 50, 150, "DC1-DC2"],
                         ["DC3", "10.1.10.0", "255.255.255.0", "Users copy", "10.1.10.20", "10.1.10.219", "8.00:00:00", 5, 195, ""],
                         ["DC1", "10.1.30.0", "255.255.255.0", "Guest Wi-Fi", "10.1.30.20", "10.1.30.219", "8.00:00:00", 50, 150, "DC1-DC2"]]),
           dhcp_options=(["Server", "ScopeId", "OptionId", "Value"],
                         [["DC1", "10.1.10.0", 6, "10.1.0.11,10.1.0.13"], ["DC1", "10.1.10.0", 3, "10.1.10.1"],
                          ["DC3", "10.1.10.0", 6, "10.1.0.11"], ["DC3", "10.1.10.0", 3, "10.1.10.1"], ["DC1", "10.1.30.0", 6, "10.1.0.11"]]),
           dhcp_failover=(["Name", "Server", "PartnerServer", "Mode", "State", "ScopeId"],
                          [["DC1-DC2", "DC1", "DC2", "HotStandby", "CommunicationInterrupted", "10.1.10.0;10.1.30.0"]]),
           dhcp_servers=(["DnsName", "IPAddress", "Authorized", "Source", "Detail"],
                         [["dc1", "10.1.0.11", "True", "AD", ""], ["dc3", "10.1.0.31", "True", "AD", ""],
                          ["", "192.168.1.1", "False", "DHCP snooping", "port Gi1/0/7"]]),
           dns_servers=(["Server", "IPAddress", "ScavengingState", "Forwarders", "Status"],
                        [["DC1", "10.1.0.11", "True", "10.0.0.53", ""], ["DC4", "10.1.0.13", "False", "", "Decommissioned 2026-09-01"]]))
    c = codes(review(load(tmp_path)))
    assert c["DHCP-FAILOVER"][0].severity == RED
    assert "10.1.0.13 (DC4, not a live DNS server)" in c["DHCP-DNS-OPTION"][0].subject
    assert c["DHCP-OVERLAP"][0].subject == "10.1.10.0/24 on DC1 and DC3"
    assert c["DHCP-NOFAILOVER"][0].subject == "DC3: 1 scope"
    assert c["DHCP-ROUTER"][0].items == ["DC1/10.1.30.0"]
    assert c["DHCP-LEASE"][0].items == ["DC1/10.1.30.0"]             # guest, 8 days against 1 day
    assert c["DHCP-ROGUE"][0].subject == "Unknown device at 192.168.1.1"


def test_reservations(tmp_path):
    estate(tmp_path,
           dhcp_reservations=(["Server", "ScopeId", "IPAddress", "ClientId", "Name"],
                              [["DC1", "10.1.10.0", "10.1.10.30", "aa-aa-aa-aa-aa-01", "PRN-1"],
                               ["DC1", "10.1.10.0", "10.1.10.31", "aa-aa-aa-aa-aa-02", "PRN-OLD"],
                               ["DC1", "10.1.20.0", "10.1.20.30", "AA:AA:AA:AA:AA:01", "PRN-1"]]),
           dhcp_leases=(["Server", "ScopeId", "IPAddress", "ClientId", "HostName", "AddressState"],
                        [["DC1", "10.1.10.0", "10.1.10.30", "aa-aa-aa-aa-aa-01", "prn-1", "ActiveReservation"]]))
    c = codes(review(load(tmp_path)))
    assert c["DHCP-RESV-DUP"][0].items == ["aa-aa-aa-aa-aa-01"]
    assert c["DHCP-RESV-STALE"][0].items == ["DC1/10.1.10.31"]


def test_dns_hygiene(tmp_path):
    old = "2026-08-01 08:00:00"
    estate(tmp_path,
           dns_zones=(["ZoneName", "IsDsIntegrated", "DynamicUpdate", "IsReverseLookupZone", "AgingEnabled"],
                      [["corp.test", "True", "Secure", "False", "False"], ["rf.test", "True", "NonsecureAndSecure", "False", "True"],
                       ["1.10.in-addr.arpa", "True", "Secure", "True", "True"]]),
           dns_servers=(["Server", "IPAddress", "ScavengingState", "Forwarders", "Status"],
                        [["DC1", "10.1.0.11", "False", "8.8.8.8", ""], ["DC4", "10.1.0.13", "", "", "Decommissioned"]]),
           dns_records=(["ZoneName", "HostName", "RecordType", "RecordData", "Timestamp"],
                        [["corp.test", "dc1", "A", "10.1.0.11", "0"], ["1.10.in-addr.arpa", "11.0", "PTR", "dc1.corp.test", "0"],
                         ["corp.test", "dc4", "A", "10.1.0.13", "0"], ["corp.test", "_ldap._tcp.dc", "SRV", "0 100 389 dc4.corp.test", "0"],
                         ["corp.test", "pc-old", "A", "10.1.10.40", old], ["corp.test", "pc-new", "A", "10.1.10.41", "2026-11-13 08:00:00"],
                         ["corp.test", "mfp", "A", "10.1.10.50", "0"], ["corp.test", "app", "A", "10.1.0.40", "0"],
                         ["corp.test", "wiki", "CNAME", "gone.corp.test", "0"], ["corp.test", "web", "CNAME", "dc1.corp.test", "0"]]))
    d = load(tmp_path)
    rv = review(d)
    c = codes(rv)
    assert c["DNS-INSECURE"][0].subject == "rf.test" and c["DNS-INSECURE"][0].severity == RED
    assert "no server scavenging" in c["DNS-AGING"][0].subject and c["DNS-AGING"][0].items == ["corp.test"]
    assert [r.name for r, _ in rv["stale"]] == ["pc-old"]
    assert c["DNS-STATIC-POOL"][0].items == ["mfp.corp.test 10.1.10.50"]
    assert c["DNS-OLD-DC"][0].count == 2
    assert {x.split()[0] for x in c["DNS-PTR"][0].items} == {"dc4.corp.test", "mfp.corp.test", "app.corp.test"}
    assert c["DNS-FORWARDERS"][0].items == ["DC1"]
    assert c["DNS-CNAME"][0].items == ["wiki.corp.test"]


def test_ip_plan(tmp_path):
    estate(tmp_path, ip_plan=(["Subnet", "Site", "Vlan", "Purpose", "Owner", "Dhcp", "Description"],
                              [["10.1.0.0/24", "HQ", 10, "servers", "Server team", "no", "Servers"],
                               ["10.1.20.0/24", "HQ", 120, "users", "", "yes", "Floor 2"],
                               ["10.1.20.128/25", "HQ", 130, "printers", "Facilities", "no", "Printers"],
                               ["10.2.0.0/24", "Branch", 10, "servers", "Server team", "no", "Branch servers"]]))
    c = codes(review(load(tmp_path)))
    assert c["IPAM-UNDOC"][0].items == ["DC1/10.1.10.0"]
    assert c["IPAM-NOSCOPE"][0].items == ["10.1.20.0/24"]
    assert c["IPAM-OVERLAP"][0].severity == RED
    assert c["IPAM-NOOWNER"][0].items == ["10.1.20.0/24"]
    assert c["IPAM-REVERSE"][0].items == ["10.2.0.0/24"]


def test_exceptions(tmp_path):
    estate(tmp_path,
           dns_zones=(["ZoneName", "IsDsIntegrated", "DynamicUpdate", "AgingEnabled"],
                      [["corp.test", "True", "Secure", "True"], ["rf.test", "True", "NonsecureAndSecure", "True"],
                       ["iot.test", "True", "NonsecureAndSecure", "True"], ["cam.test", "True", "NonsecureAndSecure", "True"]]),
           exceptions=(["Subject", "Check", "Reason", "Approver", "Ticket", "Expires"],
                       [["rf.test", "DNS-INSECURE", "vendor", "CISO", "R-1", "2027-06-30"],
                        ["iot.test", "DNS-INSECURE", "vendor", "CISO", "R-2", "2026-10-31"],
                        ["cam.test", "DNS-INSECURE", "vendor", "", "R-3", "2027-06-30"],
                        ["corp.test", "DNS-INSECURE", "old", "CISO", "R-4", "2026-11-30"]]))
    rv = review(load(tmp_path))
    c = codes(rv)
    assert sorted(f.subject for f in c["DNS-INSECURE"]) == ["cam.test", "iot.test"]       # the valid one counts
    assert c["EXC-EXPIRED"][0].severity == RED and c["EXC-INCOMPLETE"][0].subject.startswith("cam.test")
    states = {ex["exception"].subject: ex["state"] for ex in rv["exceptions"]}
    assert states == {"rf.test": "valid", "iot.test": "expired", "cam.test": "incomplete", "corp.test": "not needed"}


def test_settings_and_missing_file(tmp_path):
    estate(tmp_path)
    s = json.loads((tmp_path / "settings.json").read_text())
    s.update({"scope_amber": 40, "owners": {"DHCP": "Infra team"}, "max_lease": {"users": "1.00:00:00"}})
    (tmp_path / "settings.json").write_text(json.dumps(s))
    c = codes(review(load(tmp_path)))
    assert c["DHCP-FULL"][0].owner == "Infra team" and c["DHCP-LEASE"][0].count == 1
    (tmp_path / "dns-records.csv").unlink()
    with pytest.raises(FileNotFoundError, match="dns-records.csv"):
        load(tmp_path)


def test_demo_numbers_and_decisions(tmp_path):
    simulate.write(tmp_path / "data")
    d = load(tmp_path / "data")
    rv = review(d)
    sm = summary(d, rv)
    assert (sm["status"], sm["red"], sm["amber"], sm["scopes"], sm["busy"], sm["failover"]) == ("RED", 9, 19, 19, 2, 16)
    assert (sm["rogue"], sm["static_pool"], sm["stale"], sm["old_dc"]) == (1, 5, 735, 6)
    assert round(sm["first_full"]) == 26
    assert [x.decision for x in rv["decisions"]] == [
        "Shorten the lease on MAD Guest Wi-Fi", "Secure-only updates on wms.wingtip.example", "Add addresses to GET Handheld scanners",
        "DHCP failover for LIS-DC01", "Turn on aging and scavenging"]


def test_demo_is_deterministic(tmp_path):
    simulate.write(tmp_path / "a")
    simulate.write(tmp_path / "b")
    for f in (tmp_path / "a").iterdir():
        assert f.read_bytes() == (tmp_path / "b" / f.name).read_bytes(), f.name


def test_outputs_and_next_month(tmp_path):
    simulate.write(tmp_path / "data")
    sm = run(tmp_path / "data", tmp_path / "out", as_of=datetime(2026, 11, 14, 9))
    for f in OUTPUTS:
        assert (tmp_path / "out" / f).stat().st_size > 0, f
    html = (tmp_path / "out" / "report.html").read_text()
    assert "<script" not in html and "MAD Guest Wi-Fi" in html and "Decisions needed" in html
    pack = (tmp_path / "out" / "review-pack.md").read_text()
    assert "## Decisions needed" in pack and "[TO COMPLETE]" in pack
    # this month's scopes.csv is next month's previous-scopes.csv
    nxt = tmp_path / "next"
    nxt.mkdir()
    for f in (tmp_path / "data").iterdir():
        (nxt / f.name).write_bytes(f.read_bytes())
    (nxt / "previous-scopes.csv").write_bytes((tmp_path / "out" / "scopes.csv").read_bytes())
    d = load(nxt)
    assert len(d.previous) == len(d.scopes)
    assert all(review(d)["review"].growth(sc)[0] == 0 for sc in d.scopes)
    assert sm["status"] == "RED"
