control 'SV-233867' do
  title 'The digital signature algorithm used for DNSSEC-enabled zones must be FIPS compatible.'
  desc "The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) (FIPS 186) provides three algorithm choices:
- Digital Signature Algorithm (DSA)
- RSA
- Elliptic Curve DSA (ECDSA).

Of these three algorithms, RSA and DSA are more widely available and hence are considered candidates of choice for DNSSEC. In terms of performance, both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. Hence, RSA is the recommended algorithm as far as this guideline is concerned. 

RSA with SHA-1 is currently the only cryptographic algorithm mandated to be implemented with DNSSEC, although other algorithm suites (i.e., RSA/SHA-256, ECDSA) are also specified. It can be expected that name servers and clients will be able to use the RSA algorithm at a minimum. It is suggested that at least one Zone Signing Key (ZSK) for a zone use the RSA algorithm.

NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in NIST's DSS (FIPS 186). Support is expected for Elliptic Curve Cryptography in the DNSSEC. The migration path for USG DNSSEC operation will be to ECDSA (or similar) from RSA/SHA-1 and RSA/SHA-256 before 30 September 2015."
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable. For Infoblox Grids that run in FIPS mode, this requirement is Not Applicable.  

1. Review FIPS requirements to ensure the proper algorithms are used.  
2. Navigate to Data Management >> DNS >> Grid DNS properties. 
3. Toggle Advanced Mode and click on the "DNSSEC" tab.  
4. Validate that all Key Signing Keys (KSKs) and ZSKs use FIPS-approved algorithms.  
5. When complete, click "Cancel" to exit the "Properties" screen. 

If FIPS-approved algorithms are not used for the KSKs and ZSKs, this is a finding.

If DSA is used, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS properties.  
2. Toggle Advanced Mode and click on the "DNSSEC" tab.  
3. Follow manual key rollover procedures and update all non-compliant KSKs and ZSKs to use FIPS-approved algorithms.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37052r611121_chk'
  tag severity: 'high'
  tag gid: 'V-233867'
  tag rid: 'SV-233867r621666_rule'
  tag stig_id: 'IDNS-8X-400009'
  tag gtitle: 'SRG-APP-000516-DNS-000090'
  tag fix_id: 'F-37017r611122_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
