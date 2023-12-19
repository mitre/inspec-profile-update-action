control 'SV-215637' do
  title 'The Windows 2012 DNS Server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) [FIPS186] provides three algorithm choices:
* Digital Signature Algorithm (DSA)
* RSA
* Elliptic Curve DSA (ECDSA).

Of these three algorithms, RSA and DSA are more widely available and considered candidates of choice for DNSSEC. In terms of performance, both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. RSA is the recommended algorithm as far as this guideline is concerned. 

RSA with SHA-1 is currently the only cryptographic algorithm mandated to be implemented with DNSSEC, although other algorithm suites (i.e. RSA/SHA-256, ECDSA) are also specified.

It can be expected that name servers and clients will be able to use the RSA algorithm at the minimum. It is suggested that at least one ZSK for a zone use the RSA algorithm.

NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in the NIST's DSS[FIPS186]. It is expected that there will be support for Elliptic Curve Cryptography in the DNSSEC. The migration path for USG DNSSEC operation will be to ECDSA (or similar) from RSA/SHA-1 and RSA/SHA-256 before September 30th, 2015."
  desc 'check', 'Note: This requirement applies to any Windows DNS Server which host non-AD-integrated zones even if the DNS servers host AD-integrated zones, too. If the Windows DNS Server only hosts AD-integrated zones and does not host any file-based zones, this is not applicable.
Validate this check from the Windows 2012 DNS server being configured/reviewed.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.
Determine a valid host in the zone.

Open the Windows PowerShell prompt on the Windows 2012 DNS server being configured/reviewed.

Issue the following command:
(Replace www.zonename.mil with a FQDN of a valid host in the zone being validated. Replace ###.###.###.### with the FQDN or IP address of the Windows 2012 DNS Server hosting the signed zone.)

resolve-dnsname www.zonename.mil -server ###.###.###.### -dnssecok <enter>

Note: It is important to use the -server switch followed by the DNS Server name/IP address.

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
  desc 'fix', 'Sign or re-sign, the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones. 

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click “Sign the Zone”, either using approved saved parameters or approved custom parameters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16831r744242_chk'
  tag severity: 'medium'
  tag gid: 'V-215637'
  tag rid: 'SV-215637r744243_rule'
  tag stig_id: 'WDNS-SC-000031'
  tag gtitle: 'SRG-APP-000514-DNS-000075'
  tag fix_id: 'F-16829r572280_fix'
  tag 'documentable'
  tag legacy: ['SV-72987', 'V-58557']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
