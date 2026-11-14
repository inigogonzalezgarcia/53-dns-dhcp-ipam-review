"""Outputs: report.html (tiles, decisions, scopes by how full they are, failover, DNS zones, the IP plan reconciled, exceptions and
every finding), review-pack.md (one page for the monthly infrastructure review), and the CSVs: scopes (next month's
previous-scopes.csv), reservations-review, dns-zones, stale-records, ip-plan-review, exceptions-review, findings and actions."""
from __future__ import annotations

import csv
import html
from collections import defaultdict
from pathlib import Path

from .checks import GROUPS, RED, _lease, reverse_net, summary
from .model import FILES, Data

e = html.escape
TODO = "**[TO COMPLETE]**"


def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _d(x) -> str:
    return "" if x is None else x.isoformat()


def _day(x) -> str:
    return "–" if x is None else f"{x:%d %b %Y}"


def _p(x) -> str:
    return "–" if x is None else f"{x:.0f} %"


def _ts(x) -> str:
    return "" if x is None else x.strftime("%Y-%m-%d %H:%M")


def _flags(rv: dict) -> dict:
    """scope key -> list of finding codes."""
    out = defaultdict(list)
    for f in rv["findings"]:
        for k in f.items:
            out[k].append(f.code)
    return out


# ---------------------------------------------------------------- csv

def scope_rows(d: Data, rv: dict) -> list[list]:
    r = rv["review"]
    flags = _flags(rv)
    rows = []
    for sc in sorted(d.scopes, key=lambda x: -(x.pct or 0)):
        delta, days = r.growth(sc)
        fo = r.failover_of(sc)
        rows.append([sc.server, str(sc.net.network_address), sc.net.prefixlen, sc.name, r.site_of(sc), r.purpose_of(sc),
                     "active" if sc.active else "inactive", sc.size, sc.in_use, "" if sc.pct is None else f"{sc.pct:.1f}",
                     "" if delta is None else delta, "" if days is None else f"{days:.0f}", _lease(sc.lease), fo.name if fo else "",
                     fo.state if fo else "", sc.options.get(6, ""), sc.options.get(3, ""), "; ".join(sorted(set(flags.get(sc.key, []))))])
    return rows


def write_scopes(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["server", "scope", "prefix", "name", "site", "purpose", "state", "size", "in_use", "pct_in_use", "change_since_last",
              "days_to_full", "lease", "failover", "failover_state", "dns_servers", "router", "findings"], scope_rows(d, rv))


def write_reservations(d: Data, rv: dict, path: Path) -> None:
    flags = _flags(rv)
    seen = set()
    if d.leases is not None:
        seen = {l.mac for l in d.leases} | {str(l.ip) for l in d.leases}
    by_mac = defaultdict(int)
    for x in d.reservations:
        by_mac[x.mac] += 1
    rows = []
    for x in d.reservations:
        active = "" if d.leases is None else ("yes" if x.mac in seen or str(x.ip) in seen else "no")
        review = "duplicate MAC" if by_mac[x.mac] > 1 else "no device seen" if f"{x.server}/{x.ip}" in flags else ""
        rows.append([x.server, x.scope, str(x.ip or ""), x.mac, x.name, x.description, active, review])
    rows.sort(key=lambda r: (r[7] == "", r[0], r[2]))
    _w(path, ["server", "scope", "ip", "mac", "name", "description", "active_lease", "review"], rows)


def zone_rows(d: Data, rv: dict) -> list[list]:
    stale = defaultdict(int)
    for r, _ in rv["stale"]:
        stale[r.zone] += 1
    flags = _flags(rv)
    rows = []
    for z in d.zones:
        recs = [r for r in d.records if r.zone == z.name]
        rows.append([z.name, "reverse" if z.reverse else "forward", "yes" if z.ad else "no", z.replication, z.updates,
                     "yes" if z.aging else "no", len(recs), sum(r.dynamic for r in recs), sum(not r.dynamic for r in recs), stale[z.name],
                     "; ".join(sorted(set(flags.get(z.name, []))))])
    return rows


def write_zones(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["zone", "direction", "ad_integrated", "replication", "dynamic_updates", "aging", "records", "dynamic", "static", "stale",
              "findings"], zone_rows(d, rv))


def write_stale(d: Data, rv: dict, path: Path) -> None:
    names = defaultdict(int)
    for r in d.records:
        if r.kind == "A":
            names[r.fqdn] += 1
    rows = [[r.zone, r.name, r.kind, r.data, _ts(r.timestamp), age, "yes" if names[r.fqdn] > 1 else "no"]
            for r, age in sorted(rv["stale"], key=lambda x: -x[1])]
    _w(path, ["zone", "name", "type", "data", "timestamp", "age_days", "name_has_newer_record"], rows)


def plan_rows(d: Data, rv: dict) -> list[list]:
    if d.plan is None:
        return []
    rev = [(z.name, reverse_net(z.name)) for z in d.zones if z.reverse]
    flags = _flags(rv)
    rows = []
    for p in d.plan:
        scs = [sc for sc in d.scopes if sc.active and sc.net == p.net]
        rz = next((n for n, net in rev if net and p.net.subnet_of(net)), "")
        if p.dhcp and not scs:
            note = "DHCP planned, no scope"
        elif not p.dhcp and scs:
            note = "static in the plan, but has a scope"
        else:
            note = "ok"
        codes = sorted(set(flags.get(str(p.net), [])))
        if codes:
            note = "; ".join(codes) if note == "ok" else note + "; " + "; ".join(codes)
        rows.append([str(p.net), p.site, p.vlan, p.purpose, p.owner, "yes" if p.dhcp else "no", p.description,
                     "; ".join(f"{sc.server} {sc.name}" for sc in scs), rz, note])
    for sc in d.scopes:
        if sc.active and not any(p.net == sc.net for p in d.plan):
            rows.append([str(sc.net), "", "", "", "", "", "", f"{sc.server} {sc.name}", "", "scope not in the plan"])
    return rows


def write_plan(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["subnet", "site", "vlan", "purpose", "owner", "dhcp_expected", "description", "scopes", "reverse_zone", "note"],
       plan_rows(d, rv))


def write_exceptions(rv: dict, path: Path) -> None:
    _w(path, ["subject", "check", "reason", "approver", "ticket", "expires", "days_to_expiry", "gap_still_there", "state", "action"],
       [[x.subject, x.check, x.reason, x.approver, x.ticket, _d(x.expires), "" if ex["days"] is None else ex["days"],
         "yes" if ex["gap"] else "no", ex["state"], ex.get("action", "")] for ex in rv["exceptions"] for x in [ex["exception"]]])


def write_findings(rv: dict, path: Path) -> None:
    _w(path, ["severity", "code", "group", "title", "subject", "detail", "action", "count", "owner", "due"],
       [[f.severity, f.code, GROUPS[f.group], f.title, f.subject, f.detail, f.action, f.count, f.owner, _d(f.due)] for f in rv["findings"]])


def actions(rv: dict) -> list:
    return [(f"A-{i:03d}", f) for i, f in enumerate(rv["findings"], 1)]


def write_actions(rv: dict, path: Path) -> None:
    _w(path, ["ref", "severity", "code", "subject", "action", "count", "owner", "due", "done"],
       [[ref, f.severity, f.code, f"{f.title}: {f.subject}", f.action, f.count, f.owner, _d(f.due), ""] for ref, f in actions(rv)])


# ---------------------------------------------------------------- the review pack

def _md(x) -> str:
    return str(x).replace("|", "/").replace("\n", " ")


def pack_md(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    out = [f"# {title}", "",
           f"> Prepared on {d.as_of:%a %d %b %Y} from the exports listed at the end, for the monthly infrastructure review. Read-only: "
           "no scope, zone or record was changed. Approved, valid exceptions are not reported as findings. Thresholds are in "
           f"settings.json. Sections marked {TODO} are for the meeting.", "",
           f"**{sm['status']}. {sm['scopes']} active scopes ({sm['leases']:,} of {sm['addresses']:,} addresses in use), "
           f"{sm['busy']} at {s.scope_amber:.0f} % or more; {sm['zones']} DNS zones with {sm['records']:,} records; "
           f"{sm['red']} red and {sm['amber']} amber findings.**", "", "## Headlines", ""]
    for f in [f for f in rv["findings"] if f.severity == RED][:7]:
        out.append(f"- **{_md(f.title)}: {_md(f.subject)}.** {_md(f.detail)}")
    am = [f for f in rv["findings"] if f.severity != RED]
    if am:
        out.append("- Also: " + "; ".join(f"{_md(f.title.lower())} ({_md(f.subject)})" for f in am[:6]) + ("; …" if len(am) > 6 else "") + ".")
    out += ["", "## DHCP scopes to watch", "", "| Scope | Server | In use | Change | Full in | Lease | Failover |", "|---|---|---|---|---|---|---|"]
    for row in scope_rows(d, rv):
        if row[9] and (float(row[9]) >= s.scope_amber or (row[11] and float(row[11]) <= s.forecast_days)):
            out.append(f"| {_md(row[3])} | {row[0]} | {row[8]} / {row[7]} ({float(row[9]):.0f} %) | {f"{row[10]:+d}" if row[10] != '' else '–'} | "
                       f"{(row[11] + ' days') if row[11] else '–'} | {row[12]} | {row[13] or 'none'} {row[14]} |")
    out += ["", "## Decisions needed", "", "| # | Decision | Options | Proposed | Owner | Needed by | Outcome |", "|---|---|---|---|---|---|---|"]
    out += [f"| {x.id} | **{_md(x.decision)}**<br>{_md(x.why)} | {_md(x.options)} | {_md(x.proposed)} | {_md(x.owner)} | "
            f"{_day(x.needed_by)} | |" for x in rv["decisions"]] or ["| – | No decisions needed | | | | | |"]
    out += ["", "## Actions", "", "Every finding is an action in `actions.csv`.", "",
            "| Ref | Severity | Action | Items | Owner | Due | Done |", "|---|---|---|---|---|---|---|"]
    for ref, f in actions(rv):
        out.append(f"| {ref} | {f.severity} | **{_md(f.title)}** ({_md(f.subject)}): {_md(f.action)} | {f.count} | {_md(f.owner)} | "
                   f"{_day(f.due)} | |")
    out += ["", "## DNS zones", "", "| Zone | Updates | Aging | Records | Dynamic | Stale |", "|---|---|---|---|---|---|"]
    out += [f"| {_md(r[0])} | {r[4]} | {r[5]} | {r[6]:,} | {r[7]:,} | {r[9]:,} |" for r in zone_rows(d, rv)]
    out += ["", "## Evidence for audits (ISO 27001 / NIS2)", "",
            f"- Network services inventory: `scopes.csv` ({len(d.scopes)} scopes), `dns-zones.csv` ({sm['zones']} zones) and the IP "
            f"address plan reconciled in `ip-plan-review.csv` ({sm['plan']} subnets).",
            f"- Availability: DHCP failover on {sm['failover']} of {sm['scopes']} active scopes ({_p(sm['failover_pct'])}).",
            "- Integrity of name resolution: zones with secure updates, records of retired servers, static addresses inside DHCP "
            "pools and unauthorised DHCP servers, in `findings.csv`.",
            f"- Exceptions with approver, ticket and expiry: `exceptions-review.csv` ({sm['exceptions']} exceptions).",
            "- Treatment: actions with owner and due date in `actions.csv`; decisions and their outcome in this pack.",
            "- Trend: `scopes.csv` is next month's `previous-scopes.csv`.", "",
            "## Scope and sources", "", f"- Organisation: {s.organisation}", f"- Review date: {d.as_of:%a %d %b %Y %H:%M}" +
            (f"; previous review {s.previous_review:%d %b %Y}" if s.previous_review else ""),
            f"- Scope filling up at {s.scope_amber:.0f} %, almost full at {s.scope_red:.0f} %; forecast window {s.forecast_days} days; "
            f"a dynamic record is stale after no-refresh + refresh + {s.stale_grace_days} days.", "",
            "| Source | File | Records |", "|---|---|---|"]
    out += [f"| {FILES.get(k, k)} | `{k}` | {v:,} |" for k, v in d.sources.items()]
    out += ["", "## Notes", "", f"- Decisions taken: {TODO}", f"- Exceptions approved or closed: {TODO}", f"- Next review: {TODO}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb;
--g:#cfeedd;--a:#fbe6bd;--r:#f8d2cd;--n:#eef0f2}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;
--bad:#f2685c;--info:#5aa9f0;--g:#173527;--a:#3d2f12;--r:#45201d;--n:#232a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:24px}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.red{color:var(--bad)}.amber{color:var(--warn)}.green{color:var(--ok)}
.bar{height:12px;background:var(--n);border-radius:3px;position:relative;min-width:120px}.bar i{display:block;height:12px;border-radius:3px;background:var(--ok)}
.bar i.a{background:var(--warn)}.bar i.r{background:var(--bad)}.bar s{position:absolute;top:-3px;width:2px;height:18px;background:var(--ink)}
td.subj{min-width:150px}td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:340px}td.sm{font-size:13px}
.brk{overflow-wrap:anywhere;word-break:break-word}footer{margin-top:40px;font-size:13px}
"""


def _pill(x: str) -> str:
    return f"<span class='pill {x.lower()}'>{e(x)}</span>"


def _table(head: list[str], rows: list[str], cls: str = "") -> str:
    return (f"<div class='wrap'><table class='{cls}'><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(rows)
            + "</table></div>")


def _bar(p, amber: float, red: float) -> str:
    if p is None:
        return ""
    cls = "r" if p >= red else "a" if p >= amber else ""
    return f"<div class='bar'><i class='{cls}' style='width:{min(p, 100):.1f}%'></i><s style='left:{amber:.0f}%'></s></div>"


def render_html(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(s.organisation)} · {sm['scopes']} DHCP scopes, {sm['zones']} DNS zones, "
         f"{sm['records']:,} records and {sm['plan']} subnets in the IP plan · run on {d.as_of:%a %d %b %Y %H:%M}"
         + (f" · previous review {s.previous_review:%d %b %Y}" if s.previous_review else "") + "</p>",
         f"<span class='overall {sm['status'].lower()}'>{e(sm['status'])} · {sm['red']} red and {sm['amber']} amber findings</span>",
         "<div class='tiles'>"]
    tiles = [("Scopes over " + f"{s.scope_amber:.0f} %", str(sm["busy"]), f"of {sm['scopes']} active"),
             ("First scope full", "–" if sm["first_full"] is None else f"{sm['first_full']:.0f} days", "at this month's pace"),
             ("DHCP failover", _p(sm["failover_pct"]), f"{sm['failover']} of {sm['scopes']} scopes"),
             ("Rogue DHCP", str(sm["rogue"]), "servers not authorised"),
             ("Static in a pool", str(sm["static_pool"]), "DNS records"),
             ("Stale records", f"{sm['stale']:,}", f"of {sm['records']:,}")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(b)}</b><span class='muted'>{e(c)}</span></div>" for a, b, c in tiles]
    h.append("</div><h2>Decisions needed</h2>")
    h.append(_table(["#", "Decision", "Options", "Proposed", "Owner", "By"],
                    [f"<tr><td class='nw'>{e(x.id)}</td><td class='subj'><b>{e(x.decision)}</b><br><span class='sm muted'>{e(x.why)}</span></td>"
                     f"<td class='sm'>{e(x.options)}</td><td class='fix'>{e(x.proposed)}</td><td class='sm'>{e(x.owner)}</td>"
                     f"<td class='nw'>{e(_day(x.needed_by))}</td></tr>" for x in rv["decisions"]]
                    or ["<tr><td colspan='6'>No decisions needed.</td></tr>"]))
    h.append(f"<h2>DHCP scopes</h2><p class='muted'>Addresses in use; the line is {s.scope_amber:.0f} %. Change and days to full "
             "against the last review.</p>")
    rows = []
    for r in scope_rows(d, rv):
        p = float(r[9]) if r[9] else None
        warn = " class='red'" if r[14] and r[14].lower() != "normal" else ""
        rows.append(f"<tr><td class='subj'><b>{e(r[3])}</b><br><span class='sm muted'>{e(r[1])}/{r[2]} · {e(r[0])}</span></td>"
                    f"<td class='num'>{r[8]} / {r[7]}</td><td>{_bar(p, s.scope_amber, s.scope_red)}</td><td class='num'>{_p(p)}</td>"
                    f"<td class='num'>{'' if r[10] == '' else f'{r[10]:+d}'}</td><td class='num'>{(('> 1 year' if float(r[11]) > 365 else r[11] + ' d') if r[11] else '')}</td>"
                    f"<td class='nw'>{e(r[12])}</td><td class='sm'{warn}>{e(r[13] or 'none')}{(' · ' + e(r[14])) if r[14] else ''}</td>"
                    f"<td class='sm'>{e(r[17])}</td></tr>")
    h.append(_table(["Scope", "In use", "", "%", "Change", "Full in", "Lease", "Failover", "Findings"], rows))
    h.append("<h2>DNS zones</h2>")
    h.append(_table(["Zone", "Updates", "Aging", "Records", "Dynamic", "Static", "Stale", "Findings"],
                    [f"<tr><td class='nw'><b>{e(r[0])}</b></td><td class='sm {'red' if r[4] == 'nonsecure' else ''}'>{e(r[4])}</td>"
                     f"<td class='sm'>{e(r[5])}</td><td class='num'>{r[6]:,}</td><td class='num'>{r[7]:,}</td><td class='num'>{r[8]:,}</td>"
                     f"<td class='num'>{r[9]:,}</td><td class='sm'>{e(r[10])}</td></tr>" for r in zone_rows(d, rv)]))
    if d.plan is not None:
        notes = defaultdict(int)
        for r in plan_rows(d, rv):
            notes[r[9] if r[9] == "ok" else r[9].split(";")[0]] += 1
        h.append("<h2>IP address plan against DHCP and DNS</h2><p class='muted'>Every subnet in the plan and every scope, matched by "
                 "network; the full list is in ip-plan-review.csv.</p>")
        h.append(_table(["Result", "Subnets"], [f"<tr><td>{e(k)}</td><td class='num'>{v}</td></tr>"
                                                for k, v in sorted(notes.items(), key=lambda x: (x[0] == 'ok', -x[1]))]))
    if rv["exceptions"]:
        h.append("<h2>Exceptions</h2>")
        h.append(_table(["Subject", "Check", "Reason", "Approver / ticket", "Expires", "State", "Action"],
                        [f"<tr><td class='nw'>{e(x.subject)}</td><td class='sm'>{e(x.check)}</td><td class='sm'>{e(x.reason)}</td>"
                         f"<td class='sm'>{e(x.approver or 'none')} / {e(x.ticket or 'none')}</td><td class='nw'>{e(_day(x.expires))}</td>"
                         f"<td class='sm {'red' if ex['state'] == 'expired' else 'amber' if ex['state'] in ('incomplete', 'expiring') else ''}'>"
                         f"{e(ex['state'])}</td><td class='fix'>{e(ex.get('action', ''))}</td></tr>" for ex in rv["exceptions"]
                         for x in [ex["exception"]]]))
    h.append("<h2>All findings</h2>")
    h.append(_table(["Severity", "Group", "Subject", "Detail", "Owner", "Due"],
                    [f"<tr><td>{_pill(f.severity)}</td><td class='sm'>{e(GROUPS[f.group])}</td><td class='subj'><b>{e(f.subject)}</b><br>"
                     f"<span class='sm muted'>{e(f.title)}</span></td><td class='sm brk'>{e(f.detail)}<br><span class='muted'>→ "
                     f"{e(f.action)}</span></td><td class='sm'>{e(f.owner)}</td><td class='nw'>{e(_day(f.due))}</td></tr>"
                     for f in rv["findings"]] or ["<tr><td colspan='6'>No findings.</td></tr>"]))
    h.append("<footer class='muted'>Generated by dnsdhcpreview. Fictional demo data unless you ran it on your own exports. The one-page "
             "pack for the monthly review is review-pack.md.</footer></main></body></html>")
    return "".join(h)


__all__ = ["render_html", "pack_md", "write_scopes", "write_reservations", "write_zones", "write_stale", "write_plan",
           "write_exceptions", "write_findings", "write_actions", "actions", "scope_rows", "zone_rows", "plan_rows"]
