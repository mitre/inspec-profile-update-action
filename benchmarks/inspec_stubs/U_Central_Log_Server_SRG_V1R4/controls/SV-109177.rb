control 'SV-109177' do
  title 'The Central Log Server must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use where needed.'
  desc 'check', 'Examine the configuration. 

Verify the Central Log Server is configured to use FIPS-validated SHA-1 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification (legacy use only).

If the Central Log Server is not configured to use FIPS-validated SHA-1 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification (legacy use only), this is a finding.'
  desc 'fix', 'Configure the Central Log Server to use FIPS-validated SHA-1 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification.'
  impact 0.7
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98925r1_chk'
  tag severity: 'high'
  tag gid: 'V-100073'
  tag rid: 'SV-109177r1_rule'
  tag stig_id: 'SRG-APP-000610-AU-000050'
  tag gtitle: 'SRG-APP-000610-AU-000050'
  tag fix_id: 'F-105759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
