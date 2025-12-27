control 'SV-215603' do
  title 'The Windows 2012 DNS Server must provide its identity with returned DNS information by enabling DNSSEC and TSIG/SIG(0).'
  desc 'Weakly bound credentials can be modified without invalidating the credential; therefore, non-repudiation can be violated.

This requirement supports audit requirements that provide organizational personnel with the means to identify who produced specific information in the event of an information transfer. Organizations and/or data owners determine and approve the strength of the binding between the information producer and the information based on the security category of the information and relevant risk factors.

DNSSEC and TSIG/SIG(0) both use digital signatures to establish the identity of the producer of particular pieces of information.'
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

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
Log on to the DNS server using the account designated as Administrator or DNS Administrator.

In the DNS Manager console tree on the DNS server being validated, navigate to Forward Lookup Zones.

Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click Sign the Zone, either using saved parameters or custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16797r314284_chk'
  tag severity: 'medium'
  tag gid: 'V-215603'
  tag rid: 'SV-215603r561297_rule'
  tag stig_id: 'WDNS-IA-000005'
  tag gtitle: 'SRG-APP-000347-DNS-000041'
  tag fix_id: 'F-16795r314285_fix'
  tag 'documentable'
  tag legacy: ['SV-73069', 'V-58639']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
