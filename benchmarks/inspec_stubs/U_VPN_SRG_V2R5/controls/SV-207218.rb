control 'SV-207218' do
  title 'The VPN Gateway must use FIPS-validated SHA-2 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-2 for integrity of remote access sessions.'
  desc 'check', 'Verify the VPN Gateway uses FIPS-validated SHA-2 or higher.

If the VPN Gateway does not use FIPS-validated SHA-2 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use FIPS-validated SHA-2 or higher hash function to protect the integrity of hash message authentication code (HMAC), Key Derivation Functions (KDFs), Random Bit Generation, hash-only applications, and digital signature verification.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7478r803425_chk'
  tag severity: 'medium'
  tag gid: 'V-207218'
  tag rid: 'SV-207218r803427_rule'
  tag stig_id: 'SRG-NET-000168-VPN-000600'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-7478r803426_fix'
  tag 'documentable'
  tag legacy: ['SV-106253', 'V-97115']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
