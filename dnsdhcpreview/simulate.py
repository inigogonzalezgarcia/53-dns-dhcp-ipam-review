"""The demo: Wingtip Toys, a made-up toy retailer and distributor with a head office in Madrid, a distribution centre in Getafe and
offices in Lisbon and Paris. Writes the exports the review reads (the same columns as the PowerShell collector) to sample_data/.
Deterministic: the same files every time."""
from __future__ import annotations

import csv
import ipaddress
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

ORG = "Wingtip Toys"
DOMAIN = "corp.wingtip.example"
WMS = "wms.wingtip.example"
AS_OF = datetime(2026, 11, 14, 9, 0)
PREVIOUS = datetime(2026, 10, 14, 9, 0)

DNS = [  # name, ip, site, role, status, forwarders
    ("MAD-DC01", "10.10.0.11", "Madrid", "DC, DNS, DHCP", "", "10.0.255.53;10.0.255.54"),
    ("MAD-DC02", "10.10.0.12", "Madrid", "DC, DNS, DHCP", "", "10.0.255.53;10.0.255.54"),
    ("MAD-DC03", "10.10.0.13", "Madrid", "DC, DNS", "Decommissioned 2026-09-18", ""),
    ("GET-DC01", "10.20.0.11", "Getafe", "DC, DNS, DHCP", "", "10.0.255.53;10.0.255.54"),
    ("LIS-DC01", "10.30.0.11", "Lisbon", "DC, DNS, DHCP", "", "192.0.2.53"),
    ("PAR-DC01", "10.40.0.11", "Paris", "DC, DNS, DHCP", "", "8.8.8.8;1.1.1.1"),
]
SITE_DNS = {"MAD": "10.10.0.11,10.10.0.12", "GET": "10.20.0.11,10.10.0.13", "LIS": "10.30.0.11,10.10.0.11", "PAR": "10.40.0.11,10.10.0.12"}

# server, network, name, site, purpose, vlan, lease (days), in use today, in use last month, failover, owner in the plan
SCOPES = [
    ("MAD-DC01", "10.10.10.0/23", "MAD Floor 1 users", "MAD", "users", 110, 8, 248, 251, "MAD-DC01-MAD-DC02", "Network team"),
    ("MAD-DC01", "10.10.12.0/23", "MAD Floor 2 users", "MAD", "users", 120, 8, 290, 286, "MAD-DC01-MAD-DC02", "Network team"),
    ("MAD-DC01", "10.10.14.0/23", "MAD Floor 3 users", "MAD", "users", 130, 8, 391, 340, "MAD-DC01-MAD-DC02", "Network team"),
    ("MAD-DC01", "10.10.20.0/24", "MAD Voice", "MAD", "voice", 200, 8, 96, 97, "MAD-DC01-MAD-DC02", "Unified communications"),
    ("MAD-DC01", "10.10.30.0/24", "MAD Printers", "MAD", "printers", 300, 8, 61, 66, "MAD-DC01-MAD-DC02", "Service desk"),
    ("MAD-DC01", "10.10.40.0/22", "MAD Corporate Wi-Fi", "MAD", "wifi", 400, 1, 571, 549, "MAD-DC01-MAD-DC02", "Network team"),
    ("MAD-DC01", "10.10.50.0/24", "MAD Guest Wi-Fi", "MAD", "guest", 500, 8, 212, 196, "MAD-DC01-MAD-DC02", "Network team"),
    ("MAD-DC01", "10.10.60.0/25", "MAD Meeting rooms AV", "MAD", "av", 600, 8, 26, None, "MAD-DC01-MAD-DC02", None),
    ("GET-DC01", "10.20.10.0/24", "GET Office users", "GET", "users", 110, 8, 113, 109, "GET-DC01-MAD-DC01", "Network team"),
    ("GET-DC01", "10.20.20.0/23", "GET Handheld scanners", "GET", "scanners", 150, 8, 380, 260, "GET-DC01-MAD-DC01", "Logistics IT"),
    ("GET-DC01", "10.20.30.0/24", "GET Printers and label printers", "GET", "printers", 300, 8, 88, 86, "GET-DC01-MAD-DC01", "Logistics IT"),
    ("GET-DC01", "10.20.40.0/24", "GET Operations Wi-Fi", "GET", "wifi", 400, 1, 129, 121, "GET-DC01-MAD-DC01", ""),
    ("GET-DC01", "10.20.50.0/24", "GET Guest Wi-Fi", "GET", "guest", 500, 1, 64, 71, "GET-DC01-MAD-DC01", "Network team"),
    ("LIS-DC01", "10.40.10.0/24", "PAR Users (emergency copy, August)", "PAR", "users", 110, 8, 6, 9, "", None),
    ("LIS-DC01", "10.30.10.0/24", "LIS Users", "LIS", "users", 110, 8, 151, 148, "", "Network team"),
    ("LIS-DC01", "10.30.20.0/25", "LIS Voice", "LIS", "voice", 200, 8, 31, 31, "", ""),
    ("PAR-DC01", "10.40.10.0/24", "PAR Users", "PAR", "users", 110, 8, 129, 126, "PAR-DC01-MAD-DC02", "Network team"),
    ("PAR-DC01", "10.40.30.0/24", "PAR Showroom", "PAR", "users", 130, 8, 88, 52, "PAR-DC01-MAD-DC02", "Retail IT"),
    ("PAR-DC01", "10.40.50.0/24", "PAR Guest Wi-Fi", "PAR", "guest", 500, 1, 44, 40, "PAR-DC01-MAD-DC02", ""),
]
FAILOVERS = [("MAD-DC01-MAD-DC02", "MAD-DC01", "MAD-DC02", "LoadBalance", "Normal"),
             ("GET-DC01-MAD-DC01", "GET-DC01", "MAD-DC01", "HotStandby", "Normal"),
             ("PAR-DC01-MAD-DC02", "PAR-DC01", "MAD-DC02", "HotStandby", "CommunicationInterrupted")]
SERVERS = [("MAD-FS01", 21), ("MAD-SQL01", 22), ("MAD-APP01", 23), ("MAD-APP02", 24), ("MAD-APP03", 25), ("MAD-PRT01", 26),
           ("MAD-VC01", 27), ("MAD-BKP01", 28), ("MAD-CA01", 29), ("MAD-WSUS01", 30), ("MAD-ERP01", 31), ("MAD-ERP02", 32),
           ("MAD-WEB01", 33), ("MAD-IPAM01", 34), ("GET-WMS01", 21), ("GET-WMS02", 22), ("GET-FS01", 23), ("GET-PRT01", 24),
           ("GET-SQL01", 25), ("LIS-FS01", 21), ("LIS-PRT01", 22), ("PAR-FS01", 21), ("PAR-PRT01", 22)]
NO_PTR = {"GET-WMS01", "GET-WMS02", "GET-PRT01", "MAD-APP02", "MAD-APP03", "MAD-BKP01", "MAD-ERP02", "MAD-WEB01", "GET-SQL01"}
SITE_NET = {"MAD": "10.10", "GET": "10.20", "LIS": "10.30", "PAR": "10.40"}
# printers set up by hand with a static address inside the DHCP pool (DHCP has not leased them yet)
STATIC_IN_POOL = {"mad-mfp-31": "10.10.30.236", "mad-mfp-32": "10.10.30.237", "mad-mfp-33": "10.10.30.238", "mad-mfp-34": "10.10.30.239",
                  "get-zebra-12": "10.20.30.240", "get-zebra-14": "10.20.30.241"}


def _w(path: Path, head: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(head)
        w.writerows(rows)


def _ts(x: datetime) -> str:
    return x.strftime("%Y-%m-%d %H:%M:%S")


def _mac(rnd: random.Random, oui: str) -> str:
    return oui + "-" + "-".join(f"{rnd.randrange(256):02x}" for _ in range(3))


def _lease(days: float) -> str:
    return f"{int(days)}.00:00:00" if days >= 1 else f"{int(days * 24):02d}:00:00"


def write(folder: Path) -> None:
    rnd = random.Random(53)
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    scope_rows, option_rows, resv_rows, lease_rows, prev_rows = [], [], [], [], []
    plan_rows = []
    a_records = []           # (zone, name, ip, timestamp or None)
    used_names = set()
    reservations = []        # (server, scope, ip, mac, name, description, active)
    for srv, cidr, name, site, pur, vlan, lease_d, used, prev, fo, owner in SCOPES:
        net = ipaddress.IPv4Network(cidr)
        hosts = list(net.hosts())
        start, end = hosts[19], hosts[-10]                 # .20 to .245: the first addresses are for the gateway and statics
        pool = [a for a in hosts if start <= a <= end]
        size = len(pool)
        scope_rows.append([srv, str(net.network_address), str(net.netmask), name, str(start), str(end), "Active", _lease(lease_d),
                           used, size - used, 0, round(used / size * 100, 1), fo])
        sid = str(net.network_address)
        dns = SITE_DNS[site]
        if "emergency" in name:
            dns = SITE_DNS["LIS"]
        option_rows.append([srv, sid, 6, "DNS Servers", dns])
        option_rows.append([srv, sid, 15, "DNS Domain Name", DOMAIN if pur != "scanners" else WMS])
        if pur != "av":                                    # the new AV scope was created without a router
            option_rows.append([srv, sid, 3, "Router", str(hosts[0])])
        if prev is not None:
            prev_rows.append([srv, sid, name, size, prev, round(prev / size * 100, 1)])
        # leases: who is on the network today
        taken = rnd.sample([a for a in pool if str(a) not in STATIC_IN_POOL.values()], used)
        for i, a in enumerate(sorted(taken)):
            if pur == "users":
                h = f"wt-{site.lower()}-l{rnd.randrange(1000, 9999)}"
            elif pur == "voice":
                h = f"sep{rnd.randrange(16**12):012x}"
            elif pur == "scanners":
                h = f"get-rf-{i + 1:03d}"
            elif pur == "printers":
                h = f"{site.lower()}-prn-{i + 1:02d}" if site != "GET" else f"get-lbl-{i + 1:02d}"
            elif pur == "av":
                h = f"mad-room-{i + 1:02d}"
            elif pur == "guest":
                h = rnd.choice(["android-", "iphone-", "galaxy-", "ipad-"]) + f"{rnd.randrange(16**6):06x}"
            else:
                h = f"wt-{site.lower()}-w{rnd.randrange(1000, 9999)}"
            if h in used_names:
                h = f"{h}-{i}"
            used_names.add(h)
            m = _mac(rnd, rnd.choice(["00-15-5d", "3c-52-82", "f4-39-09", "00-1b-21", "a4-5d-36"]))
            zone = WMS if pur == "scanners" else DOMAIN
            fq = f"{h}.{zone}" if pur not in ("guest",) else h
            lease_rows.append([srv, sid, str(a), m, fq, "Active", _ts(AS_OF + timedelta(days=lease_d * rnd.uniform(0.2, 1)))])
            if pur in ("users", "scanners", "wifi", "printers", "av", "voice") and pur != "voice":
                a_records.append((zone, h, str(a), AS_OF - timedelta(hours=rnd.uniform(1, 140))))
            if pur in ("printers", "av"):
                reservations.append((srv, sid, str(a), m, h.upper(), "Reserved for the device", True))
        if owner is not None:
            plan_rows.append([cidr, {"MAD": "Madrid", "GET": "Getafe", "LIS": "Lisbon", "PAR": "Paris"}[site], vlan, pur, owner, "yes",
                              name.replace(f"{site} ", "")])
    # printers retired in the October office move: their reservations stayed
    leased = {r[2] for r in lease_rows}
    for srv, site, sid, n in (("MAD-DC01", "MAD", "10.10.30.0", 9), ("GET-DC01", "GET", "10.20.30.0", 5)):
        free = [f"{sid[:-1]}{k}" for k in range(150, 230) if f"{sid[:-1]}{k}" not in leased | set(STATIC_IN_POOL.values())]
        for k in range(n):
            reservations.append((srv, sid, free[k], _mac(rnd, "00-80-77"), f"{site}-PRN-OLD{k + 1:02d}", "Floor printer (old)", False))
    # a label printer moved to Wi-Fi and reserved in both scopes
    lbl = next(r for r in reservations if r[4] == "GET-LBL-07")
    reservations.append(("GET-DC01", "10.20.40.0", "10.20.40.31", lbl[3], "GET-LBL-07", "Label printer, now on Wi-Fi", True))
    resv_rows = [[s, sc, a, m, n, de] for s, sc, a, m, n, de, _ in reservations]
    _w(folder / "dhcp-scopes.csv", ["Server", "ScopeId", "SubnetMask", "Name", "StartRange", "EndRange", "State", "LeaseDuration",
                                    "InUse", "Free", "Reserved", "PercentageInUse", "FailoverRelationship"], scope_rows)
    option_rows.insert(0, ["MAD-DC01", "server", 15, "DNS Domain Name", DOMAIN])
    _w(folder / "dhcp-options.csv", ["Server", "ScopeId", "OptionId", "Name", "Value"], option_rows)
    _w(folder / "dhcp-reservations.csv", ["Server", "ScopeId", "IPAddress", "ClientId", "Name", "Description"], resv_rows)
    _w(folder / "dhcp-leases.csv", ["Server", "ScopeId", "IPAddress", "ClientId", "HostName", "AddressState", "LeaseExpiryTime"],
       lease_rows)
    fo_rows = []
    for fname, a, b, mode, state in FAILOVERS:
        ids = [r[1] for r in scope_rows if r[12] == fname]
        fo_rows.append([fname, a, b, mode, state, ";".join(ids)])
    _w(folder / "dhcp-failover.csv", ["Name", "Server", "PartnerServer", "Mode", "State", "ScopeId"], fo_rows)
    _w(folder / "dhcp-servers.csv", ["DnsName", "IPAddress", "Authorized", "Source", "Detail"],
       [[f"{n.lower()}.{DOMAIN}", ip, "True", "Active Directory", ""] for n, ip, _, role, st, _ in DNS if "DHCP" in role]
       + [["", "192.168.0.1", "False", "DHCP snooping on PAR-SW02",
           "offers on VLAN 130 (PAR Showroom) from port Gi1/0/14, MAC 3c-84-6a-11-20-5e (a consumer router)"]])
    _w(folder / "dns-servers.csv", ["Server", "IPAddress", "Site", "Role", "ScavengingState", "ScavengingInterval",
                                    "LastScavengeTime", "Forwarders", "Status"],
       [[n, ip, site, role, "False" if n != "MAD-DC03" else "True", "0.00:00:00" if n != "MAD-DC03" else "7.00:00:00",
         "" if n != "MAD-DC03" else "2026-09-14 02:00:00", fw, st] for n, ip, site, role, st, fw in DNS])
    # ---------------------------------------------------------------- DNS
    zones = [[DOMAIN, "Primary", "True", "Forest", "Secure", "False", "False", "7.00:00:00", "7.00:00:00"],
             [f"_msdcs.{DOMAIN}", "Primary", "True", "Forest", "Secure", "False", "False", "7.00:00:00", "7.00:00:00"],
             [WMS, "Primary", "True", "Domain", "NonsecureAndSecure", "False", "False", "7.00:00:00", "7.00:00:00"],
             ["10.10.in-addr.arpa", "Primary", "True", "Domain", "Secure", "True", "False", "7.00:00:00", "7.00:00:00"],
             ["20.10.in-addr.arpa", "Primary", "True", "Domain", "Secure", "True", "False", "7.00:00:00", "7.00:00:00"]]
    _w(folder / "dns-zones.csv", ["ZoneName", "ZoneType", "IsDsIntegrated", "ReplicationScope", "DynamicUpdate",
                                  "IsReverseLookupZone", "AgingEnabled", "NoRefreshInterval", "RefreshInterval"], zones)
    recs = []

    def ptr(a: str) -> tuple[str, str]:
        o = a.split(".")
        z = f"{o[1]}.{o[0]}.in-addr.arpa"
        return z, f"{o[3]}.{o[2]}"

    for z in (DOMAIN, WMS):
        recs.append([z, "@", "SOA", f"mad-dc01.{DOMAIN}. hostmaster.{DOMAIN}.", "0"])
    for n, ip, site, role, st, _ in DNS:
        recs.append([DOMAIN, n.lower(), "A", ip, "0"])
        recs.append([DOMAIN, "@", "NS", f"{n.lower()}.{DOMAIN}", "0"])
        recs.append([f"_msdcs.{DOMAIN}", "_ldap._tcp.dc", "SRV", f"0 100 389 {n.lower()}.{DOMAIN}", "0"])
        recs.append([f"_msdcs.{DOMAIN}", "_kerberos._tcp.dc", "SRV", f"0 100 88 {n.lower()}.{DOMAIN}", "0"])
        recs.append([DOMAIN, f"_ldap._tcp.{site}._sites", "SRV", f"0 100 389 {n.lower()}.{DOMAIN}", "0"])
        if n != "MAD-DC03" and site in ("Madrid", "Getafe") or n == "MAD-DC03":
            z, h = ptr(ip)
            recs.append([z, h, "PTR", f"{n.lower()}.{DOMAIN}", "0"])
    for n, last in SERVERS:
        ip = f"{SITE_NET[n[:3]]}.0.{last}"
        recs.append([DOMAIN, n.lower(), "A", ip, "0"])
        if n[:3] in ("MAD", "GET") and n not in NO_PTR:
            z, h = ptr(ip)
            recs.append([z, h, "PTR", f"{n.lower()}.{DOMAIN}", "0"])
    # printers set up with a static address inside the pool, outside DHCP
    for name_, a in STATIC_IN_POOL.items():
        recs.append([DOMAIN, name_, "A", a, "0"])
    for alias, target in (("intranet", "mad-web01"), ("erp", "mad-erp01"), ("print", "mad-prt01"),
                          ("intranet-old", "web-old01"), ("wiki", "confluence-old01"), ("scan2mail", "mad-smtp02")):
        recs.append([DOMAIN, alias, "CNAME", f"{target}.{DOMAIN}", "0"])
    for zone, h, a, t in a_records:
        recs.append([zone, h, "A", a, _ts(t)])
    # laptops and handhelds gone or re-imaged: their records are still there
    for i in range(612):
        site = rnd.choice(["MAD", "MAD", "MAD", "GET", "LIS", "PAR"])
        recs.append([DOMAIN, f"wt-{site.lower()}-l{rnd.randrange(1000, 9999)}x", "A",
                     f"{SITE_NET[site]}.{rnd.choice([10, 11, 12, 13, 14, 15])}.{rnd.randrange(20, 240)}",
                     _ts(AS_OF - timedelta(days=rnd.uniform(25, 420)))])
    dupes = [r for r in a_records if r[0] == DOMAIN and r[1].startswith("wt-")][:38]
    for zone, h, a, t in dupes:
        o = a.split(".")
        recs.append([zone, h, "A", f"{o[0]}.{o[1]}.{o[2]}.{(int(o[3]) + 97) % 220 + 20}", _ts(AS_OF - timedelta(days=rnd.uniform(30, 200)))])
    for i in range(85):
        recs.append([WMS, f"get-rf-old{i + 1:03d}", "A", f"10.20.{rnd.choice([20, 21])}.{rnd.randrange(20, 240)}",
                     _ts(AS_OF - timedelta(days=rnd.uniform(40, 300)))])
    _w(folder / "dns-records.csv", ["ZoneName", "HostName", "RecordType", "RecordData", "Timestamp"], recs)
    # ---------------------------------------------------------------- the IP address plan
    sites = {"MAD": "Madrid", "GET": "Getafe", "LIS": "Lisbon", "PAR": "Paris"}
    for k, v in sites.items():
        plan_rows.insert(0, [f"{SITE_NET[k]}.0.0/24", v, 10, "servers", "Windows server team", "no", "Servers and domain controllers"])
    plan_rows.append(["10.30.50.0/24", "Lisbon", 500, "guest", "Network team", "yes", "Guest Wi-Fi (new office floor)"])
    plan_rows.append(["10.40.30.128/25", "Paris", 310, "printers", "Retail IT", "no", "Showroom printers and screens"])
    _w(folder / "ip-plan.csv", ["Subnet", "Site", "Vlan", "Purpose", "Owner", "Dhcp", "Description"], plan_rows)
    _w(folder / "exceptions.csv", ["Subject", "Check", "Reason", "Approver", "Ticket", "Expires"], [
        ["get-zebra-12.corp.wingtip.example", "DNS-STATIC-POOL", "Label printer firmware only supports a static address; IP excluded "
         "on the switch port", "Head of Logistics IT", "CHG-4471", "2027-01-31"],
        ["LIS-DC01", "DHCP-NOFAILOVER", "Single server in Lisbon until the second one arrives", "IT Director", "RISK-112", "2026-10-31"],
        [WMS, "DNS-INSECURE", "The handheld vendor needs nonsecure updates for the RF guns", "", "WMS-219", "2027-03-31"],
        ["PAR-DC01", "DNS-FORWARDERS", "Public DNS during the showroom launch for the streaming partner", "IT Director", "CHG-4502",
         "2026-11-30"],
        ["MAD Floor 2 users", "DHCP-FULL", "Temporary: sales move to floor 2 in Q3", "IT Director", "CHG-4320", "2027-02-28"],
    ])
    _w(folder / "previous-scopes.csv", ["server", "scope", "name", "size", "in_use", "pct_in_use"], prev_rows)
    (folder / "settings.json").write_text(json.dumps({
        "organisation": ORG, "review_date": AS_OF.strftime("%Y-%m-%d %H:%M"), "previous_review": PREVIOUS.strftime("%Y-%m-%d"),
        "domain": DOMAIN, "scope_amber": 80, "scope_red": 90, "forecast_days": 30, "stale_grace_days": 7, "expiring_days": 30,
        "max_lease": {"guest": "08:00:00", "wifi": "1.00:00:00", "scanners": "8.00:00:00", "users": "8.00:00:00"},
        "approved_forwarders": ["10.0.255.53", "10.0.255.54"], "due_days": {"RED": 7, "AMBER": 30},
        "owners": {"DHCP": "Network team", "DNS": "Windows server team", "IPAM": "Network team",
                   "EXCEPTIONS": "Security risk manager", "ROGUE": "Security operations"}}, indent=2) + "\n", encoding="utf-8")
