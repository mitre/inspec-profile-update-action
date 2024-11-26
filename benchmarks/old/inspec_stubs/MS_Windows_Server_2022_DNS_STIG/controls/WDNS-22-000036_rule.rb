control 'WDNS-22-000036_rule' do
  title 'The secondary Windows DNS name servers must cryptographically authenticate zone transfers from primary name servers.'
  desc 'Authenticity of zone transfers within Windows Active Directory (AD)-integrated zones is accomplished by AD replication. Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific preauthorized devices can access the system.

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair, TSIG, or using PKI-based authentication, SIG(0).'
  desc 'check', 'For zones that are completely AD-integrated, this check is not a finding.

For authenticity of zone transfers between non-AD-integrated zones, DNSSEC must be implemented.

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
Expiration: 12/21/2022 10:215:28 AM
Signed: 11/22/2022 10:15:28 AM
Signer: zonename.mil
Signature: {87, 232, 34, 134...}

Name: origin-www.zonename.mil
QueryType: A
TTL: 201
Section: Answer
IP4Address: ###.###.###.###

If the results do not show the RRSIG and signature information, indicating the zone has been signed with DNSSEC, this is a finding.'
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

In the DNS Manager console tree on the DNS server being validated, navigate to "Forward Lookup Zones".

Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000036_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000036'
  tag rid: 'WDNS-22-000036_rule'
  tag stig_id: 'WDNS-22-000036'
  tag gtitle: 'SRG-APP-000394-DNS-000049'
  tag fix_id: 'F-WDNS-22-000036_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
