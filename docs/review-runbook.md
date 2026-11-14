# Monthly DNS, DHCP and IPAM review: runbook

## The cycle

1. **First working day of the month.** Run `scripts/Export-DnsDhcp.ps1`, copy last month's `output/scopes.csv` to
   `data/previous-scopes.csv`, refresh `ip-plan.csv` from the IP plan and `exceptions.csv` from the register, and run
   `python -m dnsdhcpreview review data/`.
2. **Before the meeting.** Read `review-pack.md`: the RED findings first, then the scopes to watch and the decisions. Open
   `stale-records.csv` and `reservations-review.csv` and send the lists to the owners to confirm.
3. **In the monthly infrastructure review** (network, Windows servers, service desk, security). Take the decisions, agree the
   exceptions, and fill in the outcome column of the pack.
4. **After it.** Open the RED actions as changes or tickets with the owner and due date in `actions.csv`; file the pack with the
   month's evidence.

## How to read the result

- **Availability first.** A scope over 90 %, a failover relationship that is not Normal and a rogue DHCP server can stop people
  working this week. Fix them before anything else.
- **Then name resolution.** Clients pointed at a retired DNS server, records of a retired domain controller and nonsecure zones cause
  slow logons and odd failures that look like something else.
- **Then hygiene.** Stale records, duplicate reservations, missing PTR records and gaps in the IP plan do not break anything today,
  but they are why the next incident takes longer to solve.

## Fix, accept or decide

- **Fix** when the change is small and reversible: a DHCP option, a reservation, a PTR record, a forwarder.
- **Accept with an exception** when there is a business reason and a date: a vendor that needs a static address, a site with one
  server until the second arrives. Every exception needs an approver, a ticket and an expiry.
- **Decide** when there are real options with a cost: widen a subnet or add a VLAN, change the lease policy, move a zone to secure
  updates, turn on scavenging.

## Changes without surprises

- **Leases.** A shorter lease takes effect as clients renew; check that the guest portal does not ask visitors to log in again too
  often.
- **Widening a scope.** Change the router interface and the scope in the same window; keep the old scope's leases until they
  expire.
- **Secure updates.** Move non-domain devices to DHCP registration (name protection, a DnsUpdateProxy credential) before switching
  the zone, and test with a few devices first.
- **Scavenging.** Turn on aging, wait one full no-refresh + refresh period, review the stale list, then turn on scavenging on one
  server only. Static records are never scavenged.
- **Retired domain controllers.** Metadata cleanup in Active Directory first, then the DNS records, then the DHCP option 006.

## Evidence for audits

The pack lists what an ISO 27001 or NIS2 auditor asks for: the inventory of network services, availability (failover coverage),
the integrity of name resolution (secure updates, rogue DHCP), the exceptions with approver and expiry, and the actions with owner
and date. Keep each month's pack and `scopes.csv` to show the trend.
