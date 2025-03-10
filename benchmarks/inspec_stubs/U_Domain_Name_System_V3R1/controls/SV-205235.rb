control 'SV-205235' do
  title 'Digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.'
  desc "The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) [FIPS186] provides three algorithm choices:
* Digital Signature Algorithm (DSA)
* RSA
* Elliptic Curve DSA (ECDSA).
Of these three algorithms, RSA and DSA are more widely available and hence are considered candidates of choice for DNSSEC. In terms of performance, both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. Hence, RSA is the recommended algorithm as far as this guideline is concerned. RSA with SHA-1 is currently the only cryptographic algorithm mandated to be implemented with DNSSEC, although other algorithm suites (i.e. RSA/SHA-256, ECDSA) are also specified. It can be expected that name servers and clients will be able to use the RSA algorithm at the minimum. It is suggested that at least one ZSK for a zone use the RSA algorithm.
NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in NIST's DSS[FIPS186]. It is expected that there will be support for Elliptic Curve Cryptography in the DNSSEC. The migration path for USG DNSSEC operation will be to ECDSA (or similar) from RSA/SHA-1 and RSA/SHA-256 before September 30th, 2015."
  desc 'check', 'Review the DNS implementation and documentation. Confirm the signature algorithm used for DNSSEC-enabled zones is FIPS-compatible.

If the signature algorithm used for DNSSEC-enabled zones is not FIPS-compatible, this is a finding.'
  desc 'fix', 'Regenerate signatures for all DNSSEC-enabled zones with FIPS-compatible algorithms.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5502r392618_chk'
  tag severity: 'medium'
  tag gid: 'V-205235'
  tag rid: 'SV-205235r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000090'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5502r392619_fix'
  tag 'documentable'
  tag legacy: ['SV-69225', 'V-54979']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
