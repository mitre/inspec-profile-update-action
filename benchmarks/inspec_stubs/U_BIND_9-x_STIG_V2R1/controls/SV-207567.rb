control 'SV-207567' do
  title 'A BIND 9.x server must implement NIST FIPS-validated cryptography for provisioning digital signatures and generating cryptographic hashes.'
  desc "The use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

The choice of digital signature algorithm will be based on recommended algorithms in well-known standards. NIST's Digital Signature Standard (DSS) [FIPS186] provides three algorithm choices:

- Digital Signature Algorithm (DSA)
- RSA
- Elliptic Curve DSA (ECDSA)

Of these three algorithms, RSA and DSA are more widely available and hence are considered candidates of choice for DNSSEC. In terms of performance, both RSA and DSA have comparable signature generation speeds, but DSA is much slower for signature verification. Hence, RSA is the recommended algorithm as far as this guideline is concerned. It can be expected that name servers and clients will be able to use the RSA algorithm at the minimum.

NIST's Secure Hash Standard (SHS) (FIPS 180-3) specifies SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as approved hash algorithms to be used as part of the algorithm suite for generating digital signatures using the digital signature algorithms in NIST's DSS[FIPS186].

"
  desc 'check', 'Verify that the DNSSEC and TSIG keys used by the BIND 9.x implementation are FIPS 180-3 compliant.

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.
DNSSEC KEYS:

Inspect the "named.conf" file and identify all of the DNSSEC signed zone files:

zone "example.com" {
file "signed_zone_file";
};

For each signed zone file identified, inspect the file for the "DNSKEY" records: 

86400 DNSKEY 257 3 8 (
<KEY HASH>
) ; KSK; 
86400 DNSKEY 256 3 8 (
<KEY HASH>
) ; ZSK; 

The fifth field in the above example identifies what algorithm was used to create the DNSKEY. 

If the fifth field the KSK DNSKEY is less than “8” (SHA256), this is a finding.

If the algorithm used to create the ZSK is less than “8” (SHA256), this is a finding.

TSIG KEYS: 

Inspect the "named.conf" file and identify all of the TSIG key statements: 

key tsig_example. {
algorithm hmac-SHA256;
include "tsig-example.key";
};

If each key statement does not use "hmac-SHA256" or a stronger algorithm, this is a finding.'
  desc 'fix', 'Create new DNSSEC and TSIG keys using a FIPS 180-3 approved cryptographic algorithm that meets or exceeds the strength of SHA256'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7822r283755_chk'
  tag severity: 'high'
  tag gid: 'V-207567'
  tag rid: 'SV-207567r612253_rule'
  tag stig_id: 'BIND-9X-001120'
  tag gtitle: 'SRG-APP-000514-DNS-000075'
  tag fix_id: 'F-7822r283756_fix'
  tag satisfies: ['SRG-APP-000514-DNS-000075', 'SRG-APP-000516-DNS-000090']
  tag 'documentable'
  tag legacy: ['SV-87069', 'V-72445']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
