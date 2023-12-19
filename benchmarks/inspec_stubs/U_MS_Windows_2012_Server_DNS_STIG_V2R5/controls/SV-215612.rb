control 'SV-215612' do
  title 'The Windows 2012 DNS Server must return data information in responses to internal name/address resolution queries.'
  desc 'The major threat associated with DNS forged responses or failures is the integrity of the DNS data returned in the response. The principle of DNSSEC is to mitigate this threat by providing data origin authentication, establishing trust in the source. By requiring remote clients to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service, data origin is validated.'
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

By default, when DNS servers are configured with DNSSEC signed zones, they will automatically respond to query requests, providing validating data in the response, whenever the query requests that validation. Since this takes place inherently when the zone is signed with DNSSEC, the requirement is satisfied by ensuring zones are signed.

Validate this check from the Windows 2012 DNS server being configured/reviewed.
Log on to the Windows 2012 DNS server using the account designated as Administrator or DNS Administrator.
Determine a valid host in the zone.
Open the Windows PowerShell prompt on the Windows 2012 DNS server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2012 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

NOTE: It is important to use the -server switch followed by the DNS Server name/IP address.

The result should show the "A" record results.

In addition, the results should show QueryType: RRSIG with an expiration, date signed, signer and signature, similar to the following:

Name: www.zonename.mil
QueryType: RRSIG
TTL: 189
Section: Answer
TypeCovered: CNAME
Algorithm: 8
LabelCount: 3
OriginalTtl: 300
Expiration: 11/21/2014 10:22:28 PM
Signed: 10/22/2014 10:22:28 PM
Signer: zonename.mil
Signature: {87, 232, 34, 134...}

Name: origin-www.zonename.mil
QueryType: A
TTL: 201
Section: Answer
IP4Address: ###.###.###.###

If the results do not show the RRSIG and signature information, this is a finding.'
  desc 'fix', 'Sign, or re-sign, the hosted zone(s) on the DNS server being validated.

Log on to the Windows 2012 DNS server using the account designated as Administrator or DNS Administrator.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using approved saved parameters or approved custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16806r314311_chk'
  tag severity: 'medium'
  tag gid: 'V-215612'
  tag rid: 'SV-215612r561297_rule'
  tag stig_id: 'WDNS-SC-000004'
  tag gtitle: 'SRG-APP-000420-DNS-000053'
  tag fix_id: 'F-16804r314312_fix'
  tag 'documentable'
  tag legacy: ['SV-73087', 'V-58657']
  tag cci: ['CCI-000366', 'CCI-002463']
  tag nist: ['CM-6 b', 'SC-20 (2)']
end
