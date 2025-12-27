control 'SV-234383' do
  title 'The UEM server must use FIPS-validated SHA-2 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network. 

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. 

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and use for compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only, but this is discouraged by DoD.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement. 

Satisfies:FCS_COP.1.1(2)'
  desc 'check', 'Verify the UEM server uses FIPS-validated SHA-2 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.

If the UEM server does not use FIPS-validated SHA-2 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications, this is a finding.'
  desc 'fix', 'Configure the UEM server to use FIPS-validated SHA-2 or higher hash function to protect the integrity of keyed-hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, and hash-only applications.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37568r614159_chk'
  tag severity: 'high'
  tag gid: 'V-234383'
  tag rid: 'SV-234383r879616_rule'
  tag stig_id: 'SRG-APP-000179-UEM-000110'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-37533r614160_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
