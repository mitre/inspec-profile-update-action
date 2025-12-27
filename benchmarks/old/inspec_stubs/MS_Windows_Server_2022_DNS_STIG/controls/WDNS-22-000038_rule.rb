control 'WDNS-22-000038_rule' do
  title 'The Windows 2022 DNS Server must provide its identity with returned DNS information by enabling DNSSEC and TSIG/SIG(0).'
  desc 'Weakly bound credentials can be modified without invalidating the credential; therefore, nonrepudiation can be violated.

This requirement supports audit requirements that provide organizational personnel with the means to identify who produced specific information in the event of an information transfer. Organizations and/or data owners determine and approve the strength of the binding between the information producer and the information based on the security category of the information and relevant risk factors.

DNSSEC and TSIG/SIG(0) both use digital signatures to establish the identity of the producer of pieces of information.'
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
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the account designated as Administrator or DNS Administrator.

In the DNS Manager console tree on the DNS server being validated, navigate to "Forward Lookup Zones".

Right-click the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either saved parameters or custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000038_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000038'
  tag rid: 'WDNS-22-000038_rule'
  tag stig_id: 'WDNS-22-000038'
  tag gtitle: 'SRG-APP-000347-DNS-000041'
  tag fix_id: 'F-WDNS-22-000038_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001901']
  tag nist: ['CM-6 b', 'AU-10 (1) (a)']
end
