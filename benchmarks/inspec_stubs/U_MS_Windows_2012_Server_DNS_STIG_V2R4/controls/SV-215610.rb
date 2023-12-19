control 'SV-215610' do
  title 'The Windows 2012 DNS Server must include data origin with authoritative data the system returns in response to external name/address resolution queries.'
  desc "The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. The security objective is to verify the integrity of each response received. An integral part of integrity verification is to ensure that valid data has originated from the right source. Establishing trust in the source is called data origin authentication.

The security objectives--and consequently the security services--that are required for securing the DNS query/response transaction are data origin authentication and data integrity verification.

The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF's DNSSEC standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor."
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

Authenticity of query responses is provided with DNSSEC signing of zones.

Validate this check from the Windows 2012 DNS server being configured/reviewed.
Log on to the Windows 2012 DNS server using the account designated as Administrator or DNS Administrator.
Determine a valid host in the zone.
Open the Windows PowerShell prompt on the Windows 2012 DNS server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2012 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

NOTE: It is important to use the -server switch followed by Windows 2012 DNS Server name/IP address.

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

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the SERVERS section, right-click the DNS server.

From the context menu that appears, click DNS Manager.

In the DNS Manager console tree on the DNS server being validated, navigate to Forward Lookup Zones.

Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using approved saved parameters or approved custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16804r314305_chk'
  tag severity: 'medium'
  tag gid: 'V-215610'
  tag rid: 'SV-215610r561297_rule'
  tag stig_id: 'WDNS-SC-000002'
  tag gtitle: 'SRG-APP-000213-DNS-000024'
  tag fix_id: 'F-16802r314306_fix'
  tag 'documentable'
  tag legacy: ['SV-73083', 'V-58653']
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
