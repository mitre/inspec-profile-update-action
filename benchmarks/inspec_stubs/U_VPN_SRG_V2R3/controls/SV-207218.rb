control 'SV-207218' do
  title 'The VPN Gateway must use FIPS-validated SHA-1 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification ('
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. For digital signature verification, SHA-1 is allowed for legacy-use. For all other hash function applications (e.g., HMAC, KDFs, RBG, password hashing, checksum integrity checks), the use of SHA-1 is acceptable, but discouraged in DoD. 

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the Internet) or an internal network.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Applications also include HMAC, KDFs, Random Bit Generation, and hash-only applications (e.g., hashing passwords and using SHA-1 or higher to compute a checksum). For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use where needed.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSH, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement.'
  desc 'check', 'Verify the VPN Gateway uses FIPS-validated SHA-1 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification (legacy use only).

If the VPN Gateway does not use FIPS-validated SHA-1 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification (legacy use only), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use FIPS-validated SHA-1 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification (legacy use only).'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7478r378275_chk'
  tag severity: 'medium'
  tag gid: 'V-207218'
  tag rid: 'SV-207218r608988_rule'
  tag stig_id: 'SRG-NET-000168-VPN-000600'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-7478r378276_fix'
  tag 'documentable'
  tag legacy: ['SV-106253', 'V-97115']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
