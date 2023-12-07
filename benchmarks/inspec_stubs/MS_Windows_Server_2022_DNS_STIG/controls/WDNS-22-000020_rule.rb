control 'WDNS-22-000020_rule' do
  title 'The digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.'
  desc "The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) (FIPS186) provides three algorithm choices:
- Digital Signature Algorithm (DSA).
- RSA.
- Elliptic Curve DSA (ECDSA).

Of these three algorithms, RSA and DSA are more widely available and hence are considered candidates of choice for DNSSEC. Both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. 

RSA is the recommended algorithm for this guideline. RSA with SHA-1 is currently the only cryptographic algorithm mandated to be implemented with DNSSEC, although other algorithm suites (i.e., RSA/SHA-256, ECDSA) are also specified. It can be expected that name servers and clients will be able to use the RSA algorithm at a minimum. It is suggested that at least one zone signing key (ZSK) for a zone use the RSA algorithm.

NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in NIST's DSS (FIPS186). It is expected that there will be support for Elliptic Curve Cryptography in the DNSSEC. The migration path for USG DNSSEC operation will be to ECDSA (or similar) from RSA/SHA-1 and RSA/SHA-256 before 30 September 2015."
  desc 'check', %q(Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone. 

Review the zone's RRs in the right windowpane.

Review the DNSKEY encryption in the Data column. Example: [DNSKEY][RsaSha1][31021]

Confirm the encryption algorithm specified in the DNSKEY's data is at RsaSha1, at a minimum.

If the specified encryption algorithm is not RsaSha1 or stronger, this is a finding.)
  desc 'fix', 'Sign or re-sign the hosted zone(s) on the DNS server being validated.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, right-click to select the zone (repeat for each hosted zone), point to DNSSEC, and then click "Sign the Zone" using either approved saved parameters or approved custom parameters.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000020_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000020'
  tag rid: 'WDNS-22-000020_rule'
  tag stig_id: 'WDNS-22-000020'
  tag gtitle: 'SRG-APP-000516-DNS-000090'
  tag fix_id: 'F-WDNS-22-000020_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
