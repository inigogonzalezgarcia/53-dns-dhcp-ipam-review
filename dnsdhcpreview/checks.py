"""The review: DHCP scopes (how full, how fast they fill, failover, options, leases, reservations, overlaps and rogue servers), DNS
(secure updates, aging and scavenging, stale and duplicate records, static records inside DHCP pools, leftovers of retired domain
controllers, reverse lookup, forwarders, dangling aliases) and the IP address plan against both, with exceptions, owners, due dates
and the decisions they need."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

from .model import Data, Scope, Zone, purpose

RED, AMBER, GREEN = "RED", "AMBER", "GREEN"
GROUPS = {"dhcp": "DHCP", "dns": "DNS", "ipam": "IP address plan", "exceptions": "Exceptions"}
NORMAL_FAILOVER = {"normal"}
DEFAULT_AGING = timedelta(days=7)
RED_CHECKS = {"DHCP-FULL", "DHCP-FAILOVER", "DHCP-DNS-OPTION", "DHCP-OVERLAP", "DHCP-ROGUE", "DNS-INSECURE", "DNS-STATIC-POOL",
              "DNS-OLD-DC", "IPAM-OVERLAP"}


@dataclass
class Finding:
    severity: str
    code: str
    group: str
    title: str
    subject: str
    detail: str
    action: str
    items: list = field(default_factory=list)
    owner: str = ""
    due: date | None = None

    @property
    def count(self) -> int:
        return len(self.items) or 1


@dataclass
class Decision:
    id: str
    decision: str
    why: str
    options: str
    proposed: str
    owner: str
    needed_by: date | None


def reverse_net(zone: str) -> ipaddress.IPv4Network | None:
    """'20.10.in-addr.arpa' -> 10.20.0.0/16."""
    m = re.fullmatch(r"((?:\d{1,3}\.){0,3}\d{1,3})\.in-addr\.arpa", zone)
    if not m:
        return None
    parts = list(reversed(m.group(1).split(".")))
    try:
        return ipaddress.IPv4Network(".".join(parts + ["0"] * (4 - len(parts))) + f"/{8 * len(parts)}")
    except ValueError:
        return None


def ptr_name(a: ipaddress.IPv4Address) -> str:
    return ".".join(reversed(str(a).split("."))) + ".in-addr.arpa"


class Review:
    def __init__(self, d: Data):
        self.d = d
        self.s = d.settings
        self.findings: list[Finding] = []
        self.used: set[int] = set()          # exceptions that cover a gap
        self.ex_states = self._exception_states()

    # -------------------------------------------------- exceptions
    def _exception_states(self) -> list[dict]:
        out = []
        for i, x in enumerate(self.d.exceptions):
            if not (x.approver and x.ticket and x.expires):
                st = "incomplete"
            elif x.expires < self.d.today:
                st = "expired"
            elif (x.expires - self.d.today).days <= self.s.expiring_days:
                st = "expiring"
            else:
                st = "valid"
            out.append({"i": i, "exception": x, "state": st,
                        "days": None if not x.expires else (x.expires - self.d.today).days, "gap": False})
        return out

    def exempt(self, code: str, *idents) -> bool:
        keys = {str(k).lower() for k in idents if k}
        hit = False
        for ex in self.ex_states:
            x = ex["exception"]
            if x.check == code and x.subject.lower() in keys:
                ex["gap"] = True
                if ex["state"] in ("valid", "expiring"):
                    self.used.add(ex["i"])
                    hit = True
        return hit

    def add(self, severity: str, code: str, group: str, title: str, subject: str, detail: str, action: str, items=(), owner_key=""):
        owner = self.s.owners.get(owner_key or group.upper(), group)
        due = self.d.today + timedelta(days=int(self.s.due_days.get(severity, 30)))
        self.findings.append(Finding(severity, code, group, title, subject, detail, action, list(items), owner, due))

    # -------------------------------------------------- scopes
    def plan_for(self, sc: Scope):
        if not self.d.plan:
            return None
        exact = [p for p in self.d.plan if p.net == sc.net]
        return exact[0] if exact else next((p for p in self.d.plan if sc.net.subnet_of(p.net)), None)

    def purpose_of(self, sc: Scope) -> str:
        p = self.plan_for(sc)
        return p.purpose if p and p.purpose else purpose(sc.name)

    def site_of(self, sc: Scope) -> str:
        p = self.plan_for(sc)
        return p.site if p else ""

    def failover_of(self, sc: Scope):
        for f in self.d.failovers:
            if sc.server in (f.server, f.partner) and (str(sc.net.network_address) in f.scopes or (sc.failover and sc.failover == f.name)):
                return f
        return None

    def growth(self, sc: Scope) -> tuple[int | None, float | None]:
        """(change since the last review, days until the pool is full at that pace)."""
        prev = (self.d.previous or {}).get(sc.key)
        if prev is None or not self.s.previous_review:
            return None, None
        days = max(1, (self.d.today - self.s.previous_review).days)
        delta = sc.in_use - prev
        if delta <= 0:
            return delta, None
        return delta, sc.free / (delta / days)

    def dns_ok(self) -> set:
        return {str(x.ip) for x in self.d.dns_servers if x.live and x.ip}

    def check_dhcp(self):
        d, s = self.d, self.s
        live = [sc for sc in d.scopes if sc.active]
        # utilisation and forecast
        for sc in sorted(live, key=lambda x: -(x.pct or 0)):
            pct = sc.pct
            if pct is None:
                continue
            delta, days = self.growth(sc)
            pace = "" if delta is None else f"; {delta:+d} leases since the last review" + (
                f", full in about {days:.0f} days at that pace" if days is not None else "")
            lease = sc.lease
            pur = self.purpose_of(sc)
            fix = ("shorten the lease" if lease and lease > timedelta(days=1) and pur in ("guest", "wifi") else
                   "add addresses (widen the subnet or add a scope) or move devices to another VLAN")
            label = f"{sc.name or sc.net} ({sc.server})"
            if pct >= s.scope_red and not self.exempt("DHCP-FULL", sc.name, str(sc.net.network_address)):
                self.add(RED, "DHCP-FULL", "dhcp", "Scope almost full", label,
                         f"{sc.in_use} of {sc.size} addresses in use ({pct:.0f} %), lease {_lease(lease)}{pace}.",
                         f"Before new devices fail to get an address: {fix}.", [sc.key])
            elif pct >= s.scope_amber and not self.exempt("DHCP-FULL", sc.name, str(sc.net.network_address)):
                self.add(AMBER, "DHCP-FULL", "dhcp", "Scope filling up", label,
                         f"{sc.in_use} of {sc.size} addresses in use ({pct:.0f} %), lease {_lease(lease)}{pace}.",
                         f"Plan it this month: {fix}.", [sc.key])
            elif days is not None and days <= s.forecast_days and not self.exempt("DHCP-FORECAST", sc.name, str(sc.net.network_address)):
                self.add(AMBER, "DHCP-FORECAST", "dhcp", "Scope will be full within the forecast window", label,
                         f"{pct:.0f} % in use today{pace}.", f"Act before it fills: {fix}.", [sc.key])
        # failover
        alone = defaultdict(list)
        for sc in live:
            f = self.failover_of(sc)
            if not f and not self.exempt("DHCP-NOFAILOVER", sc.server, sc.name, str(sc.net.network_address)):
                alone[sc.server].append(sc)
        for srv, scs in alone.items():
            self.add(AMBER, "DHCP-NOFAILOVER", "dhcp", "Scopes without DHCP failover", f"{srv}: {_n(len(scs), 'scope')}",
                     "If this server stops, these subnets lose new leases when the current ones expire: "
                     + ", ".join(x.name or str(x.net) for x in scs) + ".",
                     "Add a failover relationship (hot standby with another site, or load balance) and test it.", [x.key for x in scs])
        for f in d.failovers:
            if f.state and f.state.replace(" ", "").lower() not in NORMAL_FAILOVER and not self.exempt("DHCP-FAILOVER", f.name):
                self.add(RED, "DHCP-FAILOVER", "dhcp", "Failover relationship not in Normal state", f"{f.name} ({f.server} ⇄ {f.partner})",
                         f"State {f.state}, mode {f.mode or '?'}, {len(f.scopes)} scopes; the partners are not replicating leases.",
                         "Restore the link between the partners (TCP 647), check the clocks, then confirm both report Normal.",
                         f.scopes)
        # options: DNS servers and router
        ok = self.dns_ok()
        bad_dns = defaultdict(list)
        no_router = []
        for sc in live:
            vals = [v for v in re.split(r"[\s,;]+", str(sc.options.get(6, ""))) if v]
            wrong = [v for v in vals if ok and v not in ok] or ([] if vals else ["(none)"])
            if wrong and not self.exempt("DHCP-DNS-OPTION", sc.name, str(sc.net.network_address)):
                for v in wrong:
                    bad_dns[v].append(sc)
            rt = [v for v in re.split(r"[\s,;]+", str(sc.options.get(3, ""))) if v]
            try:
                good_rt = any(ipaddress.IPv4Address(v) in sc.net for v in rt)
            except ValueError:
                good_rt = False
            if not good_rt and self.purpose_of(sc) != "management" and not self.exempt("DHCP-ROUTER", sc.name, str(sc.net.network_address)):
                no_router.append(sc)
        names = {str(x.ip): x.name for x in d.dns_servers if x.ip}
        for v, scs in bad_dns.items():
            who = f"{v} ({names[v]}, not a live DNS server)" if v in names else (f"{v}, not a known DNS server" if v != "(none)" else
                                                                                  "no DNS server option")
            self.add(RED, "DHCP-DNS-OPTION", "dhcp", "Clients get a DNS server that does not answer", f"Option 006: {who}",
                     f"{_n(len(scs), 'scope')} hand{'s' if len(scs) == 1 else ''} it out: " + ", ".join(f"{x.name or x.net} ({x.server})" for x in scs) + ".",
                     "Set option 006 to the live DNS servers of the site; clients pick it up when they renew.", [x.key for x in scs])
        if no_router:
            self.add(AMBER, "DHCP-ROUTER", "dhcp", "No default gateway in the scope", _n(len(no_router), "scope"),
                     "Option 003 is missing or outside the subnet: " + ", ".join(f"{x.name or x.net} ({x.server})" for x in no_router) + ".",
                     "Set option 003 to the gateway of the VLAN.", [x.key for x in no_router])
        # lease durations
        long_ = []
        for sc in live:
            lim = s.lease_limit(self.purpose_of(sc))
            if lim and sc.lease and sc.lease > lim and not self.exempt("DHCP-LEASE", sc.name, str(sc.net.network_address)):
                long_.append((sc, lim))
        if long_:
            self.add(AMBER, "DHCP-LEASE", "dhcp", "Lease longer than the standard for the subnet", _n(len(long_), "scope"),
                     "; ".join(f"{sc.name or sc.net}: {_lease(sc.lease)} (standard {_lease(lim)})" for sc, lim in long_) + ".",
                     "Shorten the lease on guest and Wi-Fi scopes so addresses come back the same day.", [sc.key for sc, _ in long_])
        # reservations
        by_mac = defaultdict(list)
        for r in d.reservations:
            by_mac[r.mac].append(r)
        dups = {m: rs for m, rs in by_mac.items() if len(rs) > 1 and not self.exempt("DHCP-RESV-DUP", m, *(x.name for x in rs))}
        if dups:
            self.add(AMBER, "DHCP-RESV-DUP", "dhcp", "Same device reserved in two places", _n(len(dups), "MAC address"),
                     "; ".join(f"{rs[0].name or m}: " + " and ".join(f"{x.ip} ({x.scope})" for x in rs) for m, rs in dups.items()) + ".",
                     "Keep the reservation where the device is now and delete the other one.", list(dups))
        if d.leases is not None:
            seen = {(l.mac, str(l.ip)) for l in d.leases} | {l.mac for l in d.leases} | {str(l.ip) for l in d.leases}
            stale = [r for r in d.reservations if r.mac not in seen and str(r.ip) not in seen
                     and not self.exempt("DHCP-RESV-STALE", r.name, str(r.ip))]
            if stale:
                self.add(AMBER, "DHCP-RESV-STALE", "dhcp", "Reservations with no device behind them", _n(len(stale), "reservation"),
                         "No active lease for the reserved address or MAC: " + ", ".join(r.name or str(r.ip) for r in stale[:12])
                         + (" …" if len(stale) > 12 else "") + ".",
                         "Confirm with the owner and delete the ones for retired devices (the address goes back to the plan).",
                         [f"{r.server}/{r.ip}" for r in stale])
        # overlaps between servers
        seen_pairs = set()
        for a in live:
            for b in live:
                if a is b or a.server == b.server or not a.net.overlaps(b.net):
                    continue
                pair = tuple(sorted((a.key, b.key)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                fa = self.failover_of(a)
                if fa and fa is self.failover_of(b):
                    continue
                if self.exempt("DHCP-OVERLAP", str(a.net.network_address), a.name, b.name):
                    continue
                self.add(RED, "DHCP-OVERLAP", "dhcp", "The same subnet served by two servers", f"{a.net} on {a.server} and {b.server}",
                         f"'{a.name}' on {a.server} and '{b.name}' on {b.server} are both active without failover between them; "
                         "they can hand out the same address twice.",
                         "Deactivate and delete the scope on the server that should not serve this subnet, after its leases expire.",
                         list(pair))
        # rogue servers
        scope_servers = {sc.server for sc in d.scopes}
        auth = {x.name for x in d.dhcp_servers if x.authorised}
        for x in d.dhcp_servers:
            if not x.authorised and not self.exempt("DHCP-ROGUE", x.name, str(x.ip)):
                self.add(RED, "DHCP-ROGUE", "dhcp", "DHCP server not authorised in Active Directory",
                         f"{x.name} ({x.ip})" if x.name else f"Unknown device at {x.ip}",
                         f"Seen by {x.source or 'the collector'}: {x.detail or 'answering DHCP requests'}.",
                         "Find and switch off the device (or authorise it if it is legitimate); turn on DHCP snooping on the access switches.",
                         [x.name or str(x.ip)], "ROGUE")
        if d.dhcp_servers:
            for srv in sorted(scope_servers - auth):
                if not self.exempt("DHCP-ROGUE", srv):
                    self.add(RED, "DHCP-ROGUE", "dhcp", "DHCP server not authorised in Active Directory", srv,
                             "It has scopes in the export but is not in the authorised list.",
                             "Authorise it, or move its scopes to an authorised server.", [srv], "ROGUE")

    # -------------------------------------------------- DNS
    def zone_of(self, fq: str) -> Zone | None:
        best = None
        for z in self.d.zones:
            if fq == z.name or fq.endswith("." + z.name):
                if not best or len(z.name) > len(best.name):
                    best = z
        return best

    def stale_records(self) -> list[tuple]:
        out = []
        zones = {z.name: z for z in self.d.zones}
        for r in self.d.records:
            if not r.dynamic or r.kind not in ("A", "AAAA", "PTR", "CNAME"):
                continue
            z = zones.get(r.zone)
            window = ((z.no_refresh if z and z.no_refresh else DEFAULT_AGING) + (z.refresh if z and z.refresh else DEFAULT_AGING)
                      + timedelta(days=self.s.stale_grace_days))
            age = (self.d.as_of - r.timestamp).days
            if age > window.days:
                out.append((r, age))
        return out

    def check_dns(self):
        d, s = self.d, self.s
        for z in d.zones:
            if z.updates == "nonsecure" and not self.exempt("DNS-INSECURE", z.name):
                self.add(RED, "DNS-INSECURE", "dns", "Zone accepts nonsecure dynamic updates", z.name,
                         "Any device on the network can register or overwrite a name in this zone, including a server's.",
                         "Switch the zone to secure updates only; register non-domain devices through DHCP (name protection) "
                         "or with static records.", [z.name])
        dyn_no_aging = [z for z in d.zones if z.updates != "none" and not z.aging and not self.exempt("DNS-AGING", z.name)]
        scav = [x for x in d.dns_servers if x.live and x.scavenging]
        stale = self.stale_records()
        if dyn_no_aging or (d.dns_servers and not scav):
            self.add(AMBER, "DNS-AGING", "dns", "Aging and scavenging not running", _n(len(dyn_no_aging), "zone") + (
                     ", no server scavenging" if d.dns_servers and not scav else ""),
                     ("Dynamic zones without aging: " + ", ".join(z.name for z in dyn_no_aging) + ". " if dyn_no_aging else "")
                     + ("No DNS server has scavenging on, so old records are never removed." if d.dns_servers and not scav else ""),
                     "Turn on aging (7 + 7 days) on the dynamic zones and scavenging on one DNS server, after the stale "
                     "record review.", [z.name for z in dyn_no_aging])
        if stale:
            by_zone = defaultdict(int)
            for r, _ in stale:
                by_zone[r.zone] += 1
            self.add(AMBER, "DNS-STALE", "dns", "Stale dynamic records", _n(len(stale), "record"),
                     "Dynamic records not refreshed for longer than aging allows: "
                     + ", ".join(f"{z} {n}" for z, n in sorted(by_zone.items(), key=lambda x: -x[1])) + ".",
                     "Review stale-records.csv; scavenging removes them once it is on.", [f"{r.fqdn} {r.data}" for r, _ in stale])
        # static A records inside a DHCP pool
        resv = {str(r.ip) for r in d.reservations}
        live = [sc for sc in d.scopes if sc.active]
        in_pool = []
        for r in d.records:
            if r.kind != "A" or r.dynamic:
                continue
            try:
                a = ipaddress.IPv4Address(r.data)
            except ValueError:
                continue
            sc = next((x for x in live if x.in_pool(a)), None)
            if sc and str(a) not in resv and not self.exempt("DNS-STATIC-POOL", r.fqdn, r.name, r.data):
                in_pool.append((r, sc))
        if in_pool:
            self.add(RED, "DNS-STATIC-POOL", "dns", "Static addresses inside a DHCP pool", _n(len(in_pool), "record"),
                     "Static A records whose address DHCP can lease to someone else: "
                     + ", ".join(f"{r.name} {r.data} ({sc.name or sc.net})" for r, sc in in_pool) + ".",
                     "Give each device a reservation (or an address outside the pool with an exclusion) and fix the record.",
                     [f"{r.fqdn} {r.data}" for r, _ in in_pool])
        # leftovers of retired DNS servers / domain controllers
        for x in d.dns_servers:
            if x.live:
                continue
            name = x.name.lower()
            left = [r for r in d.records if (x.ip and r.data == str(x.ip)) or r.data.split(".")[0] == name or
                    r.data.split(" ")[-1].split(".")[0] == name]
            if left and not self.exempt("DNS-OLD-DC", x.name):
                kinds = defaultdict(int)
                for r in left:
                    kinds[r.kind] += 1
                self.add(RED, "DNS-OLD-DC", "dns", "Records still point to a retired server", f"{x.name} ({x.ip})",
                         f"{x.name} is {(x.status or 'retired').lower()} but {len(left)} records still point to it ("
                         + ", ".join(f"{n} {k}" for k, n in kinds.items()) + "); clients and other DCs keep trying it.",
                         "Finish the metadata cleanup in Active Directory and delete its records (SRV, NS, A and the "
                         "reverse record).", [f"{r.fqdn} {r.kind}" for r in left])
        # reverse lookup for static records
        rev = [(z, reverse_net(z.name)) for z in d.zones if z.reverse]
        ptrs = {r.fqdn for r in d.records if r.kind == "PTR"}
        no_ptr = []
        for r in d.records:
            if r.kind != "A" or r.dynamic:
                continue
            try:
                a = ipaddress.IPv4Address(r.data)
            except ValueError:
                continue
            if any(n and a in n for _, n in rev) and ptr_name(a) not in ptrs and not self.exempt("DNS-PTR", r.fqdn, r.name):
                no_ptr.append(r)
        if no_ptr:
            self.add(AMBER, "DNS-PTR", "dns", "Static records without a reverse record", _n(len(no_ptr), "record"),
                     "Reverse lookup fails for: " + ", ".join(f"{r.name} {r.data}" for r in no_ptr[:12])
                     + (" …" if len(no_ptr) > 12 else "") + ".",
                     "Create the PTR records (or tick 'Update associated pointer record' when you edit the A record).",
                     [f"{r.fqdn} {r.data}" for r in no_ptr])
        # forwarders
        if s.approved_forwarders:
            appr = set(s.approved_forwarders)
            odd = [x for x in d.dns_servers if x.live and x.forwarders and {str(f) for f in x.forwarders} != appr
                   and not self.exempt("DNS-FORWARDERS", x.name)]
            if odd:
                self.add(AMBER, "DNS-FORWARDERS", "dns", "Forwarders different from the standard", _n(len(odd), "DNS server"),
                         "; ".join(f"{x.name} forwards to {', '.join(map(str, x.forwarders))}" for x in odd)
                         + f" (standard: {', '.join(s.approved_forwarders)}).",
                         "Set the standard forwarders so every site resolves and filters the internet the same way.", [x.name for x in odd])
        # dangling aliases
        names = {r.fqdn for r in d.records}
        dangling = [r for r in d.records if r.kind == "CNAME" and self.zone_of(r.data.lower()) and r.data.lower() not in names
                    and not self.exempt("DNS-CNAME", r.fqdn, r.name)]
        if dangling:
            self.add(AMBER, "DNS-CNAME", "dns", "Aliases that point to nothing", _n(len(dangling), "CNAME record"),
                     ", ".join(f"{r.name} → {r.data}" for r in dangling) + ".",
                     "Delete them, or point them to the service that replaced the old host.", [r.fqdn for r in dangling])

    # -------------------------------------------------- IP plan
    def check_plan(self):
        d = self.d
        if d.plan is None:
            return
        undoc = [sc for sc in d.scopes if sc.active and not any(p.net == sc.net for p in d.plan)
                 and not self.exempt("IPAM-UNDOC", sc.name, str(sc.net.network_address))]
        if undoc:
            self.add(AMBER, "IPAM-UNDOC", "ipam", "DHCP scopes not in the IP address plan", _n(len(undoc), "scope"),
                     ", ".join(f"{sc.net} '{sc.name}' ({sc.server})" for sc in undoc) + ".",
                     "Add them to the plan with site, VLAN, purpose and owner, or remove the scope.", [sc.key for sc in undoc])
        nets = {sc.net for sc in d.scopes if sc.active}
        noscope = [p for p in d.plan if p.dhcp and p.net not in nets and not self.exempt("IPAM-NOSCOPE", str(p.net))]
        if noscope:
            self.add(AMBER, "IPAM-NOSCOPE", "ipam", "Planned DHCP subnets with no scope", _n(len(noscope), "subnet"),
                     ", ".join(f"{p.net} {p.description or p.purpose} ({p.site})" for p in noscope) + ".",
                     "Create the scope, or mark the subnet as static in the plan.", [str(p.net) for p in noscope])
        over = []
        for i, a in enumerate(d.plan):
            for b in d.plan[i + 1:]:
                if a.net.overlaps(b.net) and not self.exempt("IPAM-OVERLAP", str(a.net), str(b.net)):
                    over.append((a, b))
        for a, b in over:
            self.add(RED, "IPAM-OVERLAP", "ipam", "Overlapping subnets in the plan", f"{a.net} and {b.net}",
                     f"'{a.description or a.purpose}' ({a.site}, VLAN {a.vlan or '?'}) and '{b.description or b.purpose}' "
                     f"({b.site}, VLAN {b.vlan or '?'}) share addresses.",
                     "Correct the plan and, if both exist on the network, re-address the smaller one.", [str(a.net), str(b.net)])
        noowner = [p for p in d.plan if not p.owner and not self.exempt("IPAM-NOOWNER", str(p.net))]
        if noowner:
            self.add(AMBER, "IPAM-NOOWNER", "ipam", "Subnets without an owner", _n(len(noowner), "subnet"),
                     ", ".join(f"{p.net} {p.description or p.purpose}" for p in noowner) + ".",
                     "Name the team that decides who gets addresses there.", [str(p.net) for p in noowner])
        rev = [reverse_net(z.name) for z in d.zones if z.reverse]
        norev = [p for p in d.plan if not any(n and p.net.subnet_of(n) for n in rev) and not self.exempt("IPAM-REVERSE", str(p.net))]
        if norev:
            sites = sorted({p.site for p in norev if p.site})
            self.add(AMBER, "IPAM-REVERSE", "ipam", "Subnets with no reverse lookup zone", _n(len(norev), "subnet"),
                     "No in-addr.arpa zone covers: " + ", ".join(str(p.net) for p in norev) + (f" ({', '.join(sites)})." if sites else "."),
                     "Create the reverse zones (AD-integrated, secure updates) so DHCP and servers register PTR records.",
                     [str(p.net) for p in norev])

    # -------------------------------------------------- exceptions
    def check_exceptions(self):
        for ex in self.ex_states:
            x, st = ex["exception"], ex["state"]
            if st == "expired" and ex["gap"]:
                sev = RED if x.check in RED_CHECKS else AMBER
                self.add(sev, "EXC-EXPIRED", "exceptions", "Exception expired and the gap is still there", f"{x.subject} · {x.check}",
                         f"Expired on {x.expires:%d %b %Y} ({x.reason or 'no reason'}; {x.approver or 'no approver'}, {x.ticket or 'no ticket'}). "
                         "It no longer counts.", "Fix the gap or renew the exception with the risk owner.", [x.subject], "EXCEPTIONS")
            elif st == "incomplete" and ex["gap"]:
                miss = [k for k, v in (("approver", x.approver), ("ticket", x.ticket), ("expiry", x.expires)) if not v]
                self.add(AMBER, "EXC-INCOMPLETE", "exceptions", "Exception without approver, ticket or expiry", f"{x.subject} · {x.check}",
                         f"Missing: {', '.join(miss)}. It does not count until it is complete.",
                         "Complete it with the risk owner, or fix the gap.", [x.subject], "EXCEPTIONS")
            elif st == "expiring" and ex["gap"]:
                self.add(AMBER, "EXC-EXPIRING", "exceptions", "Exception expires soon", f"{x.subject} · {x.check}",
                         f"Expires on {x.expires:%d %b %Y}, in {ex['days']} days.", "Fix the gap before then, or renew it.",
                         [x.subject], "EXCEPTIONS")
            ex["action"] = {"valid": "none" if ex["gap"] else "close it: the gap is gone",
                            "expiring": "fix or renew before it expires", "expired": "fix the gap or renew",
                            "incomplete": "add approver, ticket and expiry"}[st] if ex["gap"] or st == "valid" else "close it: the gap is gone"
            if not ex["gap"]:
                ex["state"] = "not needed" if st in ("valid", "expiring") else st

    # -------------------------------------------------- decisions
    def decisions(self) -> list[Decision]:
        out = []
        n = 0

        def add(decision, why, options, proposed, owner_key, sev):
            nonlocal n
            n += 1
            due = self.d.today + timedelta(days=int(self.s.due_days.get(sev, 30)))
            out.append(Decision(f"D{n}", decision, why, options, proposed, self.s.owners.get(owner_key, owner_key), due))

        for f in self.findings:
            if f.code in ("DHCP-FULL", "DHCP-FORECAST") and (f.severity == RED or f.code == "DHCP-FORECAST"):
                sc = next(x for x in self.d.scopes if x.key == f.items[0])
                pur = self.purpose_of(sc)
                if pur in ("guest", "wifi") and sc.lease and sc.lease > timedelta(days=1):
                    add(f"Shorten the lease on {sc.name or sc.net}", f.detail, "1 day / 8 hours / widen the subnet",
                        "8 hours: visitors stay a day, the pool frees itself overnight; no change to the network.", "DHCP", f.severity)
                else:
                    wider = f"/{sc.net.prefixlen - 1}"
                    add(f"Add addresses to {sc.name or sc.net}", f.detail,
                        f"Widen the subnet to a {wider} (router and switch change) / a second scope on a new VLAN / shorter lease",
                        f"Widen to a {wider} in the next change window; a shorter lease only buys days.", "DHCP", f.severity)
            elif f.code == "DNS-INSECURE":
                add(f"Secure-only updates on {f.subject}", "Devices that are not domain members register here today.",
                    "Secure only + DHCP registers for them (name protection) / keep it nonsecure on its own VLAN with an exception",
                    "Secure only, with DHCP registering on behalf of the handhelds; test with ten devices first.", "DNS", f.severity)
            elif f.code == "DNS-AGING":
                add("Turn on aging and scavenging", f.detail,
                    "7 + 7 days on the dynamic zones, scavenging on one server / leave it off and clean by hand every quarter",
                    "7 + 7 days and scavenging every 7 days on one server, after the owners confirm the stale list.", "DNS", f.severity)
            elif f.code == "DHCP-NOFAILOVER":
                add(f"DHCP failover for {f.subject.split(':')[0]}", f.detail,
                    "Hot standby with a server at another site / load balance with a second local server / accept the risk",
                    "Hot standby with the Madrid server (5 % reserve) over the existing WAN.", "DHCP", f.severity)
        return out

    def run(self) -> dict:
        self.check_dhcp()
        self.check_dns()
        self.check_plan()
        self.check_exceptions()
        order = {RED: 0, AMBER: 1}
        self.findings.sort(key=lambda f: (order[f.severity], list(GROUPS).index(f.group)))
        return {"findings": self.findings, "decisions": self.decisions(), "exceptions": self.ex_states,
                "stale": self.stale_records(), "review": self}


def _n(n: int, word: str) -> str:
    """'1 scope', '3 scopes', '1 MAC address', '2 MAC addresses'."""
    if n == 1:
        return f"1 {word}"
    return f"{n} {word}es" if word.endswith(("s", "x")) else f"{n} {word}s"


def _lease(x: timedelta | None) -> str:
    if x is None:
        return "?"
    if x.total_seconds() % 86400 == 0:
        n = int(x.total_seconds() // 86400)
        return f"{n} day" + ("s" if n != 1 else "")
    h = x.total_seconds() / 3600
    return f"{h:g} hours" if h != 1 else "1 hour"


def review(d: Data) -> dict:
    return Review(d).run()


def summary(d: Data, rv: dict) -> dict:
    fs = rv["findings"]
    red = sum(f.severity == RED for f in fs)
    amber = sum(f.severity == AMBER for f in fs)
    r: Review = rv["review"]
    live = [sc for sc in d.scopes if sc.active]
    busy = [sc for sc in live if (sc.pct or 0) >= d.settings.scope_amber]
    days = [g for g in (r.growth(sc)[1] for sc in live) if g is not None]
    fo = [sc for sc in live if r.failover_of(sc)]
    def count(code):
        return sum(f.count for f in fs if f.code == code)
    return {"status": RED if red else AMBER if amber else GREEN, "red": red, "amber": amber, "scopes": len(live),
            "busy": len(busy), "first_full": min(days) if days else None,
            "failover_pct": len(fo) / len(live) * 100 if live else None, "failover": len(fo),
            "rogue": count("DHCP-ROGUE"), "insecure": count("DNS-INSECURE"), "stale": len(rv["stale"]),
            "static_pool": count("DNS-STATIC-POOL"), "old_dc": count("DNS-OLD-DC"), "zones": len(d.zones), "records": len(d.records),
            "leases": sum(sc.in_use for sc in live), "addresses": sum(sc.size for sc in live),
            "plan": len(d.plan or []), "exceptions": len(d.exceptions)}
