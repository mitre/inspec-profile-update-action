control 'WDNS-22-000071_rule' do
  title 'The Windows 2022 DNS Server must maintain the integrity of information during reception.'
  desc 'Information can be unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Validate this check from the Windows 2022 DNS Server being configured/reviewed.

Log on to the Windows 2022 DNS Server using the account designated as Administrator or DNS Administrator.

Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2022 DNS Server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2022 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

Note: It is important to use the -server switch followed by the DNS server name/IP address.

The result should show the "A" record results.

In addition, the results should show QueryType: RRSIG with an expiration, date signed, signer, and signature, similar to the following:

Name: www.zonename.mil
QueryType: RRSIG
TTL: 189
Section: Answer
TypeCovered: CNAME
Algorithm: 8
LabelCount: 3
OriginalTtl: 300
Expiration: 11/21/2022 10:22:28 PM
Signed: 10/22/2022 10:22:28 PM
Signer: zonename.mil
Signature: {87, 232, 34, 134...}

Name: origin-www.zonename.mil
QueryType: A
TTL: 201
Section: Answer
IP4Address: ###.###.###.###

If the results do not show the RRSIG and signature information, this is a finding.'
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the Windows 2022 DNS Server using the Domain Admin or Enterprise Admin account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand "Forward Lookup Zones".

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000071_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000071'
  tag rid: 'WDNS-22-000071_rule'
  tag stig_id: 'WDNS-22-000071'
  tag gtitle: 'SRG-APP-000442-DNS-000067'
  tag fix_id: 'F-WDNS-22-000071_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
