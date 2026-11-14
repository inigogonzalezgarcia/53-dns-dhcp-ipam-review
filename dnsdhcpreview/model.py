"""Loading: the DHCP scopes with their statistics (dhcp-scopes.csv), the scope and server options (dhcp-options.csv), the reservations
(dhcp-reservations.csv), the active leases (dhcp-leases.csv), the failover relationships (dhcp-failover.csv), the DHCP servers seen and
authorised (dhcp-servers.csv), the DNS servers (dns-servers.csv), zones (dns-zones.csv) and records (dns-records.csv), the IP address
plan (ip-plan.csv) and, when present, the exceptions (exceptions.csv) and last month's scopes (previous-scopes.csv). Forgiving column
names, into plain dataclasses."""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

SCOPE_ALIASES = {
    "server": ["Server", "ComputerName", "DhcpServer", "DHCP server", "PSComputerName"],
    "scope": ["ScopeId", "Scope", "Scope id", "Subnet", "Network"],
    "mask": ["SubnetMask", "Mask", "Subnet mask"],
    "name": ["Name", "Scope name", "ScopeName"],
    "start": ["StartRange", "Start", "Start range", "First address"],
    "end": ["EndRange", "End", "End range", "Last address"],
    "state": ["State", "Status", "Scope state"],
    "lease": ["LeaseDuration", "Lease duration", "Lease", "Lease time"],
    "in_use": ["InUse", "In use", "AddressesInUse", "Leased", "Used"],
    "free": ["Free", "AddressesFree", "Available"],
    "reserved": ["Reserved", "Reservations"],
    "failover": ["Failover", "FailoverRelationship", "Relationship", "Failover relationship"],
}
OPTION_ALIASES = {
    "server": ["Server", "ComputerName", "PSComputerName"],
    "scope": ["ScopeId", "Scope", "Level"],
    "option": ["OptionId", "Option", "Option id", "Code"],
    "value": ["Value", "Values", "Data"],
}
RESERVATION_ALIASES = {
    "server": ["Server", "ComputerName", "PSComputerName"],
    "scope": ["ScopeId", "Scope"],
    "ip": ["IPAddress", "IP", "Address", "IP address"],
    "mac": ["ClientId", "MAC", "MacAddress", "MAC address", "Client id"],
    "name": ["Name", "Device", "Hostname"],
    "description": ["Description", "Comment", "Notes"],
}
LEASE_ALIASES = {
    "server": ["Server", "ComputerName", "PSComputerName"],
    "scope": ["ScopeId", "Scope"],
    "ip": ["IPAddress", "IP", "Address"],
    "mac": ["ClientId", "MAC", "MacAddress"],
    "host": ["HostName", "Host", "Name", "Client name"],
    "state": ["AddressState", "State", "Status"],
    "expires": ["LeaseExpiryTime", "Expires", "Lease expiry", "Expiry"],
}
FAILOVER_ALIASES = {
    "name": ["Name", "Relationship", "Failover"],
    "server": ["Server", "ComputerName", "PrimaryServerName", "PSComputerName"],
    "partner": ["PartnerServer", "Partner", "Partner server"],
    "mode": ["Mode", "Failover mode"],
    "state": ["State", "Status"],
    "scopes": ["ScopeId", "ScopeIds", "Scopes"],
}
SERVER_ALIASES = {
    "server": ["DnsName", "Server", "Name", "Hostname"],
    "ip": ["IPAddress", "IP", "Address"],
    "authorised": ["Authorized", "Authorised", "In AD", "AuthorizedInAD"],
    "source": ["Source", "Seen by", "Found by"],
    "detail": ["Detail", "Notes", "Port", "Where"],
}
DNS_SERVER_ALIASES = {
    "server": ["Server", "ComputerName", "Name", "DnsServer"],
    "ip": ["IPAddress", "IP", "Address"],
    "site": ["Site", "AD site", "Location"],
    "role": ["Role", "Type"],
    "scavenging": ["ScavengingState", "Scavenging", "Scavenging enabled"],
    "scavenging_interval": ["ScavengingInterval", "Scavenging interval"],
    "last_scavenge": ["LastScavengeTime", "Last scavenge", "LastScavenge"],
    "forwarders": ["Forwarders", "Forwarder", "IPAddress forwarders"],
    "status": ["Status", "State", "Lifecycle"],
}
ZONE_ALIASES = {
    "zone": ["ZoneName", "Zone", "Name"],
    "kind": ["ZoneType", "Type"],
    "ad": ["IsDsIntegrated", "AD integrated", "DsIntegrated"],
    "replication": ["ReplicationScope", "Replication", "Replication scope"],
    "updates": ["DynamicUpdate", "Dynamic update", "Dynamic updates", "Updates"],
    "reverse": ["IsReverseLookupZone", "Reverse", "Reverse lookup"],
    "aging": ["AgingEnabled", "Aging", "Aging enabled"],
    "no_refresh": ["NoRefreshInterval", "No-refresh", "No refresh interval"],
    "refresh": ["RefreshInterval", "Refresh", "Refresh interval"],
}
RECORD_ALIASES = {
    "zone": ["ZoneName", "Zone"],
    "name": ["HostName", "Name", "Record name", "Host"],
    "kind": ["RecordType", "Type", "Record type"],
    "data": ["RecordData", "Data", "Value", "Target", "IPAddress"],
    "timestamp": ["Timestamp", "Time stamp", "TimeStamp", "Aging timestamp"],
}
PLAN_ALIASES = {
    "subnet": ["Subnet", "Prefix", "Network", "CIDR", "Range"],
    "site": ["Site", "Location", "Office"],
    "vlan": ["Vlan", "VLAN", "VLAN id", "VlanId"],
    "purpose": ["Purpose", "Use", "Usage", "Type", "Role"],
    "owner": ["Owner", "Responsible", "Team"],
    "dhcp": ["Dhcp", "DHCP", "DHCP expected", "Dynamic"],
    "description": ["Description", "Name", "Notes"],
}
EXCEPTION_ALIASES = {
    "subject": ["Subject", "Scope", "Zone", "Record", "Object", "Name"],
    "check": ["Check", "Code", "Finding", "Control"],
    "reason": ["Reason", "Justification", "Business reason", "Description"],
    "approver": ["Approver", "Approved by", "Risk owner", "Accepted by"],
    "ticket": ["Ticket", "Change", "Reference", "Risk id"],
    "expires": ["Expires", "Expiry", "Expiry date", "Valid until", "End date"],
}
PREVIOUS_ALIASES = {
    "server": ["server", "Server"],
    "scope": ["scope", "ScopeId", "Scope"],
    "in_use": ["in_use", "InUse", "In use"],
    "pct": ["pct_in_use", "PercentageInUse", "Pct"],
}
YES = {"yes", "y", "true", "1", "x", "si", "enabled", "on"}
NO = {"no", "n", "false", "0", "disabled", "off", "none"}
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M", "%d/%m/%Y", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%d %b %Y")
FILES = {"dhcp-scopes.csv": "DHCP scopes and statistics", "dhcp-options.csv": "DHCP options", "dhcp-reservations.csv": "Reservations",
         "dhcp-leases.csv": "Active leases", "dhcp-failover.csv": "Failover relationships", "dhcp-servers.csv": "DHCP servers",
         "dns-servers.csv": "DNS servers", "dns-zones.csv": "DNS zones", "dns-records.csv": "DNS records", "ip-plan.csv": "IP address plan",
         "exceptions.csv": "Exceptions", "previous-scopes.csv": "Last review"}
REQUIRED = ("dhcp-scopes.csv", "dns-zones.csv", "dns-records.csv")
DEFAULT_OWNERS = {"DHCP": "Network team", "DNS": "Windows server team", "IPAM": "Network team", "EXCEPTIONS": "Security risk manager",
                  "ROGUE": "Security operations"}


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(ch for ch in s if not unicodedata.combining(ch))).strip()


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip()
    if not s or _norm(s) in {"n a", "na", "none", "null", "never", "static", "0"}:
        return None
    s = re.sub(r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", "", s)
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def parse_d(v) -> date | None:
    x = parse_dt(v)
    return x.date() if x else None


def num(v) -> float | None:
    s = str(v or "").strip().rstrip("%").strip()
    if not re.fullmatch(r"-?\d+([.,]\d+)?", s):
        return None
    return float(s.replace(",", "."))


def yes_no(v) -> bool | None:
    n = _norm(v)
    if n in YES:
        return True
    if n in NO:
        return False
    return None


def host(v) -> str:
    """Short upper-case name: 'mad-dc01.corp.wingtip.example.' -> 'MAD-DC01'."""
    return str(v or "").strip().rstrip(".").split(".")[0].upper()


def fqdn(v) -> str:
    return str(v or "").strip().rstrip(".").lower()


def mac(v) -> str:
    """'00-15-5D-0A-01-FF', '00:15:5d:0a:01:ff' or '00155d0a01ff' -> '00-15-5d-0a-01-ff'."""
    h = re.sub(r"[^0-9a-f]", "", str(v or "").lower())
    return "-".join(h[i:i + 2] for i in range(0, len(h), 2)) if len(h) == 12 else str(v or "").strip().lower()


def ip(v) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(v or "").strip())
    except ValueError:
        return None


def ips(v) -> list[ipaddress.IPv4Address]:
    return [x for x in (ip(p) for p in re.split(r"[\s,;]+", str(v or "")) if p) if x]


def network(v, mask=None) -> ipaddress.IPv4Network | None:
    s = str(v or "").strip()
    if not s:
        return None
    try:
        if mask and "/" not in s:
            return ipaddress.IPv4Network(f"{s}/{str(mask).strip()}", strict=False)
        return ipaddress.IPv4Network(s, strict=False)
    except ValueError:
        return None


def duration(v) -> timedelta | None:
    """'8.00:00:00', '04:00:00', '1d', '8 days', '4h' or minutes as a number."""
    s = str(v or "").strip().lower()
    m = re.fullmatch(r"(?:(\d+)\.)?(\d{1,2}):(\d{2}):(\d{2})", s)
    if m:
        return timedelta(days=int(m.group(1) or 0), hours=int(m.group(2)), minutes=int(m.group(3)), seconds=int(m.group(4)))
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(d|day|days|h|hr|hour|hours|m|min|mins|minutes)?", s)
    if m:
        n, u = float(m.group(1)), (m.group(2) or "min")[0]
        return timedelta(days=n) if u == "d" else timedelta(hours=n) if u == "h" else timedelta(minutes=n)
    return None


def updates(v) -> str:
    """secure, nonsecure, none."""
    n = _norm(v).replace(" ", "")
    if n in {"nonsecureandsecure", "nonsecure", "insecure", "unsecure", "1"}:
        return "nonsecure"
    if n in {"secure", "secureonly", "2"}:
        return "secure"
    return "none"


def purpose(v) -> str:
    n = _norm(v)
    toks = n.split()
    for key, words in (("guest", ("guest", "visitor", "byod")), ("voice", ("voice", "voip", "phone")),
                       ("printers", ("print", "label")), ("scanners", ("scanner", "handheld", "rf")),
                       ("servers", ("server", "datacenter")), ("management", ("management", "mgmt", "infra")),
                       ("av", ("av", "room", "meeting")), ("iot", ("iot", "camera", "cctv", "building")),
                       ("wifi", ("wifi", "wireless", "wlan")), ("users", ("user", "client", "desk", "staff", "floor"))):
        if any((t == w if len(w) <= 3 else t.startswith(w)) for t in toks for w in words) or ("wi fi" in n and key == "wifi"):
            return key
    return n or "other"


def _read(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = fh.readline()
        fh.seek(0)
        delim = max(",;\t", key=header.count)
        reader = csv.DictReader(fh, delimiter=delim)
        return list(reader.fieldnames or []), list(reader)


def _map(fields: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    heads = {_norm(h): h for h in fields}
    cols = {}
    for k, names in aliases.items():
        for n in names + [k.replace("_", " ")]:
            if _norm(n) in heads and heads[_norm(n)] not in cols.values():
                cols[k] = heads[_norm(n)]
                break
    return cols


def _rows(path: Path, aliases: dict[str, list[str]]) -> list[dict]:
    fields, raw = _read(path)
    cols = _map(fields, aliases)
    return [{k: (r.get(c) or "").strip() for k, c in cols.items()} for r in raw]


# ---------------------------------------------------------------- records

@dataclass
class Scope:
    server: str
    net: ipaddress.IPv4Network
    name: str = ""
    start: ipaddress.IPv4Address | None = None
    end: ipaddress.IPv4Address | None = None
    active: bool = True
    lease: timedelta | None = None
    in_use: int = 0
    free: int = 0
    reserved: int = 0
    failover: str = ""
    options: dict = field(default_factory=dict)        # option id -> value, scope level over server level

    @property
    def key(self) -> str:
        return f"{self.server}/{self.net.network_address}"

    @property
    def size(self) -> int:
        return self.in_use + self.free

    @property
    def pct(self) -> float | None:
        return None if not self.size else self.in_use / self.size * 100

    def in_pool(self, a) -> bool:
        return bool(a and self.start and self.end and self.start <= a <= self.end)


@dataclass
class Reservation:
    server: str
    scope: str
    ip: ipaddress.IPv4Address | None
    mac: str
    name: str = ""
    description: str = ""


@dataclass
class Lease:
    server: str
    scope: str
    ip: ipaddress.IPv4Address | None
    mac: str
    host: str = ""
    state: str = ""


@dataclass
class Failover:
    name: str
    server: str
    partner: str
    mode: str = ""
    state: str = ""
    scopes: list = field(default_factory=list)


@dataclass
class DhcpServer:
    name: str
    ip: ipaddress.IPv4Address | None
    authorised: bool
    source: str = ""
    detail: str = ""


@dataclass
class DnsServer:
    name: str
    ip: ipaddress.IPv4Address | None
    site: str = ""
    role: str = ""
    scavenging: bool | None = None
    last_scavenge: datetime | None = None
    forwarders: list = field(default_factory=list)
    status: str = ""

    @property
    def live(self) -> bool:
        return not any(w in _norm(self.status).split() for w in ("decommissioned", "retired", "removed", "demoted", "offline"))


@dataclass
class Zone:
    name: str
    kind: str = ""
    ad: bool = False
    replication: str = ""
    updates: str = "none"
    reverse: bool = False
    aging: bool = False
    no_refresh: timedelta | None = None
    refresh: timedelta | None = None


@dataclass
class Record:
    zone: str
    name: str
    kind: str
    data: str
    timestamp: datetime | None = None

    @property
    def fqdn(self) -> str:
        return self.zone if self.name in ("@", "") else f"{self.name}.{self.zone}".lower()

    @property
    def dynamic(self) -> bool:
        return self.timestamp is not None


@dataclass
class Subnet:
    net: ipaddress.IPv4Network
    site: str = ""
    vlan: str = ""
    purpose: str = ""
    owner: str = ""
    dhcp: bool = False
    description: str = ""


@dataclass
class Exception_:
    subject: str
    check: str
    reason: str = ""
    approver: str = ""
    ticket: str = ""
    expires: date | None = None


@dataclass
class Settings:
    organisation: str = "Your organisation"
    review_date: datetime | None = None
    previous_review: date | None = None
    scope_amber: float = 80.0
    scope_red: float = 90.0
    forecast_days: int = 30
    stale_grace_days: int = 7
    expiring_days: int = 30
    max_lease: dict = field(default_factory=lambda: {"guest": "1.00:00:00", "wifi": "1.00:00:00", "scanners": "8.00:00:00",
                                                     "users": "8.00:00:00"})
    approved_forwarders: list = field(default_factory=list)
    due_days: dict = field(default_factory=lambda: {"RED": 7, "AMBER": 30})
    owners: dict = field(default_factory=lambda: dict(DEFAULT_OWNERS))
    domain: str = ""

    @classmethod
    def load(cls, path: Path) -> "Settings":
        s = cls()
        if not path.exists():
            return s
        raw = json.loads(path.read_text(encoding="utf-8"))
        for k, v in raw.items():
            if k in ("review_date",):
                setattr(s, k, parse_dt(v))
            elif k == "previous_review":
                setattr(s, k, parse_d(v))
            elif k == "owners":
                s.owners.update(v)
            elif k == "max_lease":
                s.max_lease.update(v)
            elif hasattr(s, k):
                setattr(s, k, v)
        return s

    def lease_limit(self, purpose_: str) -> timedelta | None:
        return duration(self.max_lease.get(purpose_, ""))


@dataclass
class Data:
    settings: Settings
    as_of: datetime
    scopes: list
    reservations: list
    leases: list | None
    failovers: list
    dhcp_servers: list
    dns_servers: list
    zones: list
    records: list
    plan: list | None
    exceptions: list
    previous: dict | None
    sources: dict = field(default_factory=dict)

    @property
    def today(self) -> date:
        return self.as_of.date()


def load(folder: Path, as_of: datetime | None = None) -> Data:
    folder = Path(folder)
    missing = [f for f in REQUIRED if not (folder / f).exists()]
    if missing:
        raise FileNotFoundError(f"missing in {folder}: {', '.join(missing)}")
    s = Settings.load(folder / "settings.json")
    when = as_of or s.review_date or datetime.now().replace(second=0, microsecond=0)
    sources: dict[str, int] = {}

    def rows(name: str, aliases: dict) -> list[dict] | None:
        p = folder / name
        if not p.exists():
            return None
        r = _rows(p, aliases)
        sources[name] = len(r)
        return r

    options: dict[tuple[str, str], dict] = {}
    for r in rows("dhcp-options.csv", OPTION_ALIASES) or []:
        code = re.sub(r"\D", "", r.get("option", ""))
        if code:
            lvl = "server" if _norm(r.get("scope")) in {"", "server"} else str(network(r.get("scope"), "32").network_address)
            options.setdefault((host(r.get("server")), lvl), {})[int(code)] = r.get("value", "")
    scopes = []
    for r in rows("dhcp-scopes.csv", SCOPE_ALIASES) or []:
        net = network(r.get("scope"), r.get("mask") or None)
        if not net:
            continue
        srv = host(r.get("server"))
        opts = dict(options.get((srv, "server"), {}))
        opts.update(options.get((srv, str(net.network_address)), {}))
        scopes.append(Scope(srv, net, r.get("name", ""), ip(r.get("start")), ip(r.get("end")),
                            _norm(r.get("state")) not in {"inactive", "disabled", "deactivated"}, duration(r.get("lease")),
                            int(num(r.get("in_use")) or 0), int(num(r.get("free")) or 0), int(num(r.get("reserved")) or 0),
                            r.get("failover", ""), opts))
    if not scopes:
        raise ValueError("dhcp-scopes.csv has no scope with a valid network")
    reservations = [Reservation(host(r.get("server")), r.get("scope", ""), ip(r.get("ip")), mac(r.get("mac")), r.get("name", ""),
                                r.get("description", "")) for r in rows("dhcp-reservations.csv", RESERVATION_ALIASES) or []]
    lr = rows("dhcp-leases.csv", LEASE_ALIASES)
    leases = None if lr is None else [Lease(host(r.get("server")), r.get("scope", ""), ip(r.get("ip")), mac(r.get("mac")),
                                            fqdn(r.get("host")), r.get("state", "")) for r in lr]
    failovers = [Failover(r.get("name", ""), host(r.get("server")), host(r.get("partner")), r.get("mode", ""), r.get("state", ""),
                          [x for x in re.split(r"[\s,;]+", r.get("scopes", "")) if x])
                 for r in rows("dhcp-failover.csv", FAILOVER_ALIASES) or []]
    dhcp_servers = [DhcpServer(host(r.get("server")), ip(r.get("ip")), bool(yes_no(r.get("authorised"))),
                               r.get("source", ""), r.get("detail", "")) for r in rows("dhcp-servers.csv", SERVER_ALIASES) or []]
    dns_servers = [DnsServer(host(r.get("server")), ip(r.get("ip")), r.get("site", ""), r.get("role", ""), yes_no(r.get("scavenging")),
                             parse_dt(r.get("last_scavenge")), ips(r.get("forwarders")), r.get("status", ""))
                   for r in rows("dns-servers.csv", DNS_SERVER_ALIASES) or []]
    zones = [Zone(fqdn(r.get("zone")), r.get("kind", ""), bool(yes_no(r.get("ad"))), r.get("replication", ""), updates(r.get("updates")),
                  bool(yes_no(r.get("reverse"))) or fqdn(r.get("zone")).endswith(".in-addr.arpa"), bool(yes_no(r.get("aging"))),
                  duration(r.get("no_refresh")), duration(r.get("refresh"))) for r in rows("dns-zones.csv", ZONE_ALIASES) or []]
    records = [Record(fqdn(r.get("zone")), fqdn(r.get("name")) or "@", r.get("kind", "").upper(), r.get("data", "").strip().rstrip("."),
                      parse_dt(r.get("timestamp"))) for r in rows("dns-records.csv", RECORD_ALIASES) or []]
    pr = rows("ip-plan.csv", PLAN_ALIASES)
    plan = None if pr is None else [Subnet(n, r.get("site", ""), r.get("vlan", ""), purpose(r.get("purpose")), r.get("owner", ""),
                                           bool(yes_no(r.get("dhcp"))), r.get("description", ""))
                                    for r in pr if (n := network(r.get("subnet")))]
    exceptions = [Exception_(r.get("subject", ""), r.get("check", "").upper(), r.get("reason", ""), r.get("approver", ""),
                             r.get("ticket", ""), parse_d(r.get("expires"))) for r in rows("exceptions.csv", EXCEPTION_ALIASES) or []]
    prev = rows("previous-scopes.csv", PREVIOUS_ALIASES)
    previous = None if prev is None else {f"{host(r.get('server'))}/{r.get('scope')}": int(num(r.get("in_use")) or 0) for r in prev}
    return Data(s, when, scopes, reservations, leases, failovers, dhcp_servers, dns_servers, zones, records, plan, exceptions, previous,
                sources)
