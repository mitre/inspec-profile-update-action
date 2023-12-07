control 'WDNS-22-000062_rule' do
  title 'The Windows 2022 DNS Server must protect the authenticity of dynamic updates via transaction signing.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.

The combination of signing DNS zones by DNSSEC and requiring clients to send their dynamic updates securely ensures the authenticity of those DNS records when providing query responses for them.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Once resource records are received by a DNS server via a secure dynamic update, the resource records will automatically become signed by DNSSEC if the zone was originally signed by DNSSEC. Authenticity of query responses for resource records dynamically updated can be validated by querying for whether the zone/record is signed by DNSSEC.

Validate this check from the Windows 2022 DNS Server being configured/reviewed.

Log on to the Windows 2022 DNS Server using the account designated as Administrator or DNS Administrator.

Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2022 DNS Server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace 131.77.60.235 with the FQDN or IP address of the Windows 2022 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

Note: It is important to use the -server switch followed by the DNS server name/IP address.

The result should show the "A" record results.

In addition, the results should show QueryType: RRSIG with an Expirations, date signed, signer, and signature, similar to the following:

Name : www.zonename.mil
QueryType : RRSIG
TTL : 189
Section : Answer
TypeCovered : CNAME
Algorithm : 8
LabelCount : 3
OriginalTtl : 300
Expiration : 11/21/2014 10:22:28 PM
Signed : 10/22/2014 10:22:28 PM
Signer : zonename.mil
Signature : {87, 232, 34, 134...}

Name : origin-www.zonename.mil
QueryType : A
TTL : 201
Section : Answer
IP4Address : 156.112.108.76

If the results do not show the RRSIG and signature information, this is a finding.'
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the Windows 2022 DNS Server using the account designated as Administrator or DNS Administrator.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

In the DNS Manager console tree on the DNS server being validated, navigate to "Forward Lookup Zones".

Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000062_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000062'
  tag rid: 'WDNS-22-000062_rule'
  tag stig_id: 'WDNS-22-000062'
  tag gtitle: 'SRG-APP-000219-DNS-000029'
  tag fix_id: 'F-WDNS-22-000062_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
