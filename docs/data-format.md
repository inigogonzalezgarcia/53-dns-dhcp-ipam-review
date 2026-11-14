# Data format and rules

Every file is a CSV with a header row (comma, semicolon or tab). Column names are matched loosely: case, spaces and punctuation do not
matter, and the usual names from the PowerShell cmdlets and the admin consoles are accepted (the first name below is the one
`scripts/Export-DnsDhcp.ps1` writes).

## Files

| File | Required | Columns | From |
|---|---|---|---|
| `dhcp-scopes.csv` | yes | Server, ScopeId, SubnetMask, Name, StartRange, EndRange, State, LeaseDuration, InUse, Free, Reserved, FailoverRelationship | `Get-DhcpServerv4Scope` + `Get-DhcpServerv4ScopeStatistics` |
| `dhcp-options.csv` | | Server, ScopeId (`server` for server options), OptionId, Value | `Get-DhcpServerv4OptionValue` |
| `dhcp-reservations.csv` | | Server, ScopeId, IPAddress, ClientId, Name, Description | `Get-DhcpServerv4Reservation` |
| `dhcp-leases.csv` | | Server, ScopeId, IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime | `Get-DhcpServerv4Lease` (active only) |
| `dhcp-failover.csv` | | Name, Server, PartnerServer, Mode, State, ScopeId (`;`-separated) | `Get-DhcpServerv4Failover` |
| `dhcp-servers.csv` | | DnsName, IPAddress, Authorized, Source, Detail | `Get-DhcpServerInDC`, plus rows you add from DHCP snooping or a scan |
| `dns-servers.csv` | | Server, IPAddress, Site, Role, ScavengingState, ScavengingInterval, LastScavengeTime, Forwarders, Status | `Get-DnsServerScavenging`, `Get-DnsServerForwarder`; add retired servers by hand with Status `Decommissioned <date>` |
| `dns-zones.csv` | yes | ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsReverseLookupZone, AgingEnabled, NoRefreshInterval, RefreshInterval | `Get-DnsServerZone` + `Get-DnsServerZoneAging` |
| `dns-records.csv` | yes | ZoneName, HostName, RecordType, RecordData, Timestamp (`0` or empty for static records) | `Get-DnsServerResourceRecord` |
| `ip-plan.csv` | | Subnet (CIDR), Site, Vlan, Purpose, Owner, Dhcp (yes/no), Description | your IP address plan or IPAM export |
| `exceptions.csv` | | Subject, Check, Reason, Approver, Ticket, Expires | your exceptions register |
| `previous-scopes.csv` | | server, scope, in_use | last month's `output/scopes.csv` |
| `settings.json` | | see below | |

Durations are read as `8.00:00:00`, `04:00:00`, `8d`, `4h` or minutes. MAC addresses in any format. Purpose comes from the IP plan,
or from the scope name when the subnet is not in the plan: guest, wifi, users, voice, printers, scanners, av, servers, management, iot.

## Settings

```json
{
  "organisation": "Wingtip Toys",
  "review_date": "2026-11-14 09:00",
  "previous_review": "2026-10-14",
  "scope_amber": 80, "scope_red": 90, "forecast_days": 30,
  "stale_grace_days": 7, "expiring_days": 30,
  "max_lease": {"guest": "08:00:00", "wifi": "1.00:00:00", "scanners": "8.00:00:00", "users": "8.00:00:00"},
  "approved_forwarders": ["10.0.255.53", "10.0.255.54"],
  "due_days": {"RED": 7, "AMBER": 30},
  "owners": {"DHCP": "Network team", "DNS": "Windows server team", "IPAM": "Network team",
             "EXCEPTIONS": "Security risk manager", "ROGUE": "Security operations"}
}
```

## Rules

| Code | Rule | Severity |
|---|---|---|
| DHCP-FULL | Active scope at `scope_red` % or more; at `scope_amber` % or more | RED; AMBER |
| DHCP-FORECAST | Below `scope_amber`, but at the growth since the last review the free addresses run out within `forecast_days` | AMBER |
| DHCP-NOFAILOVER | Active scope in no failover relationship (one finding per server) | AMBER |
| DHCP-FAILOVER | Failover relationship in any state other than Normal | RED |
| DHCP-DNS-OPTION | Option 006 missing, or listing an address that is not a live DNS server in `dns-servers.csv` | RED |
| DHCP-ROUTER | Option 003 missing or outside the subnet (management subnets excepted) | AMBER |
| DHCP-LEASE | Lease longer than `max_lease` for the purpose of the subnet | AMBER |
| DHCP-RESV-DUP | The same MAC reserved more than once | AMBER |
| DHCP-RESV-STALE | Reservation with no active lease for its address or MAC (needs `dhcp-leases.csv`) | AMBER |
| DHCP-OVERLAP | Overlapping active scopes on two servers that are not partners in the same failover relationship | RED |
| DHCP-ROGUE | A DHCP server seen that is not authorised in AD, or a server with scopes that is not in the authorised list | RED |
| DNS-INSECURE | Zone that accepts nonsecure dynamic updates | RED |
| DNS-AGING | Dynamic zone without aging, or no live DNS server with scavenging on | AMBER |
| DNS-STALE | Dynamic A, AAAA, PTR or CNAME record older than no-refresh + refresh (7 + 7 days if not set) + `stale_grace_days` | AMBER |
| DNS-STATIC-POOL | Static A record whose address is inside an active DHCP pool and is not a reservation | RED |
| DNS-OLD-DC | Records (A, NS, SRV, PTR, CNAME) that point to a DNS server marked as decommissioned | RED |
| DNS-PTR | Static A record inside a reverse zone with no PTR record | AMBER |
| DNS-FORWARDERS | Live DNS server whose forwarders are not `approved_forwarders` | AMBER |
| DNS-CNAME | CNAME pointing to a name in one of your zones that has no record | AMBER |
| IPAM-UNDOC | Active scope whose network is not in the plan | AMBER |
| IPAM-NOSCOPE | Plan subnet marked for DHCP with no active scope | AMBER |
| IPAM-OVERLAP | Two subnets in the plan that overlap | RED |
| IPAM-NOOWNER | Plan subnet without an owner | AMBER |
| IPAM-REVERSE | Plan subnet not covered by any reverse lookup zone | AMBER |
| EXC-EXPIRED | Exception expired and the gap is still there | RED for the RED checks above; AMBER otherwise |
| EXC-EXPIRING, EXC-INCOMPLETE | Expires within `expiring_days`; no approver, ticket or expiry (it does not count) | AMBER |

An exception applies when its `Check` is the code above and its `Subject` is the scope name or ScopeId, the server, the zone, the
record's full name or the subnet, depending on the check. A valid or expiring exception removes the item from the finding; an
expired or incomplete one does not.

Every finding gets an owner from `owners` (by group: DHCP, DNS, IPAM; ROGUE for rogue servers; EXCEPTIONS) and a due date from
`due_days`. A RED or forecast scope, a nonsecure zone, missing aging and scopes without failover also become decisions.
