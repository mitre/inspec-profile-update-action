control 'SV-207264' do
  title 'The VPN Gateway must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. Use only SHA-2 for Digital signature generation applications and functions. SHA-2 is strongly preferred for use by DoD for non-signature generation functions.

Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. For digital signature verification, SHA-1 is allowed for legacy-use. For all other hash function applications (e.g., HMAC, KDFs, RBG, password hashing, checksum integrity checks), the use of SHA-1 is acceptable, but discouraged in DoD. 

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use only if needed for business critical applications.'
  desc 'check', 'Verify the VPN Gateway uses FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).

If the VPN Gateway does not use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7524r378413_chk'
  tag severity: 'medium'
  tag gid: 'V-207264'
  tag rid: 'SV-207264r608988_rule'
  tag stig_id: 'SRG-NET-000585-VPN-002420'
  tag gtitle: 'SRG-NET-000585'
  tag fix_id: 'F-7524r378414_fix'
  tag 'documentable'
  tag legacy: ['SV-106361', 'V-97223']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
