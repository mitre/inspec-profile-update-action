control 'SV-207256' do
  title 'For site-to-site VPN Gateway must store only cryptographic representations of Pre-shared Keys (PSKs).'
  desc "Pre-shared keys need to be protected at all times, and encryption is the standard method for protecting passwords. If PSKs are not encrypted, they can be plainly read and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

PSKs used for site-to-site VPNs are considered by the SRG as a type of password. If this shared secret is already encrypted and not in plaintext, this meets this requirement. This requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption. This method uses a one-way hashing encryption algorithm with a salt value to validate a user's password without having to store the actual password. Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security.

Use a keyed hash message authentication code (HMAC). HMAC calculates a message authentication code via a cryptographic hash function used in conjunction with an encryption key. The key must be protected as with any private key."
  desc 'check', 'Verify the VPN Gateway stores only cryptographic representations of the PSK.

If the VPN Gateway does not store only cryptographic representations of the PSK, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to store only cryptographic representations of the PSK.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7516r378389_chk'
  tag severity: 'medium'
  tag gid: 'V-207256'
  tag rid: 'SV-207256r608988_rule'
  tag stig_id: 'SRG-NET-000522-VPN-002320'
  tag gtitle: 'SRG-NET-000522'
  tag fix_id: 'F-7516r378390_fix'
  tag 'documentable'
  tag legacy: ['SV-106345', 'V-97207']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
