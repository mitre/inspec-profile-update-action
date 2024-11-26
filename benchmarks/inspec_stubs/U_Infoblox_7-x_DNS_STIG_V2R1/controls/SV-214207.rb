control 'SV-214207' do
  title 'Digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.'
  desc "The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) [FIPS186] provides three algorithm choices:
* Digital Signature Algorithm (DSA)
* RSA
* Elliptic Curve DSA (ECDSA).
Of these three algorithms, RSA and DSA are more widely available and hence are considered candidates of choice for DNSSEC. In terms of performance, both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. Hence, RSA is the recommended algorithm as far as this guideline is concerned. RSA with SHA-1 is currently the only cryptographic algorithm mandated to be implemented with DNSSEC, although other algorithm suites (i.e. RSA/SHA-256, ECDSA) are also specified. It can be expected that name servers and clients will be able to use the RSA algorithm at the minimum. It is suggested that at least one ZSK for a zone use the RSA algorithm.
NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in NIST's DSS[FIPS186]. It is expected that there will be support for Elliptic Curve Cryptography in the DNSSEC. The migration path for USG DNSSEC operation will be to ECDSA (or similar) from RSA/SHA-1 and RSA/SHA-256 before September 30th, 2015."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Infoblox supports FIPS compliant DSA and RSA; SHA-1, SHA-256, and SHA-512 algorithms.

Navigate to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Validate that all Key Signing Keys (KSK) and Zone Signing Keys (ZSK) utilize FIPS approved algorithms.
When complete, click "Cancel" to exit the "Properties" screen.

If FIPS approved algorithms are not used for the Key Signing Keys (KSK) and Zone Signing Keys (ZSK), this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Follow manual key rollover procedures and update all non-compliant Key Signing Keys (KSK) and Zone Signing Keys (ZSK) to utilize FIPS-approved algorithms.'
  impact 0.7
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15422r295884_chk'
  tag severity: 'high'
  tag gid: 'V-214207'
  tag rid: 'SV-214207r612370_rule'
  tag stig_id: 'IDNS-7X-000780'
  tag gtitle: 'SRG-APP-000516-DNS-000090'
  tag fix_id: 'F-15420r295885_fix'
  tag 'documentable'
  tag legacy: ['SV-83099', 'V-68609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
