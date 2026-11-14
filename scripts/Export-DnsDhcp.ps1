<#
.SYNOPSIS
    Read-only export of the Windows Server DHCP and DNS configuration for dnsdhcpreview.

.DESCRIPTION
    Reads, and never changes:
      - DHCP (DhcpServer module): authorised servers in Active Directory, IPv4 scopes with their statistics, scope and server
        options, reservations, active leases and failover relationships.
      - DNS (DnsServer module): server settings (scavenging, forwarders), zones with their aging settings, and the records of
        every forward and reverse zone (SOA, NS, A, AAAA, CNAME, PTR and SRV).
    Writes the CSV files the review reads into -OutputFolder. Scopes in a failover relationship are exported once, from the first
    server that has them, so their statistics are not counted twice.

    Run it from a management workstation with RSAT (DHCP and DNS tools), as an account that can read the DHCP and DNS servers
    (DHCP Users and a read-only DNS role, or Domain Admins in a lab).

.EXAMPLE
    .\scripts\Export-DnsDhcp.ps1 -OutputFolder .\data
    Uses the DHCP servers authorised in Active Directory and the domain controllers as DNS servers.

.EXAMPLE
    .\scripts\Export-DnsDhcp.ps1 -OutputFolder .\data -DhcpServers mad-dc01,get-dc01 -DnsServers mad-dc01 -SkipLeases
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputFolder,
    [string[]] $DhcpServers,
    [string[]] $DnsServers,
    [switch] $SkipLeases
)

$ErrorActionPreference = 'Stop'
Import-Module DhcpServer, DnsServer
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null
function Save($rows, $name) { $rows | Export-Csv -Path (Join-Path $OutputFolder $name) -NoTypeInformation -Encoding UTF8 }

# ---------------------------------------------------------------- DHCP
$authorised = Get-DhcpServerInDC
Save ($authorised | Select-Object DnsName, IPAddress, @{n='Authorized';e={'True'}}, @{n='Source';e={'Active Directory'}},
      @{n='Detail';e={''}}) 'dhcp-servers.csv'
if (-not $DhcpServers) { $DhcpServers = $authorised.DnsName }

$scopes = @(); $options = @(); $reservations = @(); $leases = @(); $failovers = @{}; $done = @{}
foreach ($srv in $DhcpServers) {
    Write-Host "DHCP $srv"
    $fo = @(Get-DhcpServerv4Failover -ComputerName $srv -ErrorAction SilentlyContinue)
    foreach ($f in $fo) {
        if (-not $failovers.ContainsKey($f.Name)) {
            $failovers[$f.Name] = [pscustomobject]@{ Name = $f.Name; Server = $srv; PartnerServer = $f.PartnerServer; Mode = $f.Mode
                                                     State = $f.State; ScopeId = ($f.ScopeId -join ';') }
        }
    }
    foreach ($o in Get-DhcpServerv4OptionValue -ComputerName $srv) {
        $options += [pscustomobject]@{ Server = $srv; ScopeId = 'server'; OptionId = $o.OptionId; Name = $o.Name; Value = ($o.Value -join ',') }
    }
    foreach ($sc in Get-DhcpServerv4Scope -ComputerName $srv) {
        $id = $sc.ScopeId.IPAddressToString
        $rel = ($fo | Where-Object { $_.ScopeId -contains $sc.ScopeId } | Select-Object -First 1).Name
        if ($rel -and $done.ContainsKey($id)) { continue }          # already exported from the failover partner
        $done[$id] = $true
        $st = Get-DhcpServerv4ScopeStatistics -ComputerName $srv -ScopeId $sc.ScopeId
        $scopes += [pscustomobject]@{ Server = $srv; ScopeId = $id; SubnetMask = $sc.SubnetMask; Name = $sc.Name
            StartRange = $sc.StartRange; EndRange = $sc.EndRange; State = $sc.State; LeaseDuration = $sc.LeaseDuration
            InUse = $st.InUse; Free = $st.Free; Reserved = $st.Reserved; PercentageInUse = [math]::Round($st.PercentageInUse, 1)
            FailoverRelationship = $rel }
        foreach ($o in Get-DhcpServerv4OptionValue -ComputerName $srv -ScopeId $sc.ScopeId) {
            $options += [pscustomobject]@{ Server = $srv; ScopeId = $id; OptionId = $o.OptionId; Name = $o.Name; Value = ($o.Value -join ',') }
        }
        $reservations += Get-DhcpServerv4Reservation -ComputerName $srv -ScopeId $sc.ScopeId |
            Select-Object @{n='Server';e={$srv}}, @{n='ScopeId';e={$id}}, @{n='IPAddress';e={$_.IPAddress.IPAddressToString}},
                          ClientId, Name, Description
        if (-not $SkipLeases) {
            $leases += Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $sc.ScopeId |
                Where-Object { $_.AddressState -like 'Active*' } |
                Select-Object @{n='Server';e={$srv}}, @{n='ScopeId';e={$id}}, @{n='IPAddress';e={$_.IPAddress.IPAddressToString}},
                              ClientId, HostName, AddressState, @{n='LeaseExpiryTime';e={$_.LeaseExpiryTime.ToString('yyyy-MM-dd HH:mm:ss')}}
        }
    }
}
Save $scopes 'dhcp-scopes.csv'
Save $options 'dhcp-options.csv'
Save $reservations 'dhcp-reservations.csv'
Save $failovers.Values 'dhcp-failover.csv'
if (-not $SkipLeases) { Save $leases 'dhcp-leases.csv' }

# ---------------------------------------------------------------- DNS
if (-not $DnsServers) { $DnsServers = (Get-ADDomainController -Filter *).HostName }
$servers = foreach ($srv in $DnsServers) {
    Write-Host "DNS $srv"
    $sc = Get-DnsServerScavenging -ComputerName $srv
    $fw = Get-DnsServerForwarder -ComputerName $srv
    [pscustomobject]@{ Server = $srv; IPAddress = ([System.Net.Dns]::GetHostAddresses($srv) | Where-Object AddressFamily -eq 'InterNetwork' |
                           Select-Object -First 1).IPAddressToString
                       Site = ''; Role = 'DNS'; ScavengingState = $sc.ScavengingState; ScavengingInterval = $sc.ScavengingInterval
                       LastScavengeTime = $sc.LastScavengeTime; Forwarders = ($fw.IPAddress.IPAddressToString -join ';'); Status = '' }
}
Save $servers 'dns-servers.csv'

# Zones and records are read from the first DNS server (AD-integrated zones replicate)
$first = $DnsServers[0]
$zones = Get-DnsServerZone -ComputerName $first | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }
Save ($zones | ForEach-Object {
    $ag = Get-DnsServerZoneAging -ComputerName $first -Name $_.ZoneName -ErrorAction SilentlyContinue
    [pscustomobject]@{ ZoneName = $_.ZoneName; ZoneType = $_.ZoneType; IsDsIntegrated = $_.IsDsIntegrated
                       ReplicationScope = $_.ReplicationScope; DynamicUpdate = $_.DynamicUpdate; IsReverseLookupZone = $_.IsReverseLookupZone
                       AgingEnabled = $ag.AgingEnabled; NoRefreshInterval = $ag.NoRefreshInterval; RefreshInterval = $ag.RefreshInterval }
}) 'dns-zones.csv'

$records = foreach ($z in $zones) {
    $wanted = 'A', 'AAAA', 'CNAME', 'PTR', 'NS', 'SRV', 'SOA'
    foreach ($r in Get-DnsServerResourceRecord -ComputerName $first -ZoneName $z.ZoneName | Where-Object RecordType -in $wanted) {
        $data = switch ($r.RecordType) {
            'A'     { $r.RecordData.IPv4Address.IPAddressToString }
            'AAAA'  { $r.RecordData.IPv6Address.IPAddressToString }
            'CNAME' { $r.RecordData.HostNameAlias }
            'PTR'   { $r.RecordData.PtrDomainName }
            'NS'    { $r.RecordData.NameServer }
            'SRV'   { "$($r.RecordData.Priority) $($r.RecordData.Weight) $($r.RecordData.Port) $($r.RecordData.DomainName)" }
            'SOA'   { "$($r.RecordData.PrimaryServer) $($r.RecordData.ResponsiblePerson)" }
            default { '' }
        }
        [pscustomobject]@{ ZoneName = $z.ZoneName; HostName = $r.HostName; RecordType = $r.RecordType; RecordData = $data
                           Timestamp = if ($r.Timestamp) { $r.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '0' } }
    }
}
Save $records 'dns-records.csv'

Write-Host "Done. Add ip-plan.csv (your IP address plan), exceptions.csv and settings.json, add retired DNS servers to"
Write-Host "dns-servers.csv with Status 'Decommissioned <date>', and copy last month's output\scopes.csv as previous-scopes.csv."
