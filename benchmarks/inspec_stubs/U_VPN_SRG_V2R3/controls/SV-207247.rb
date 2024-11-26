control 'SV-207247' do
  title 'For site-to-site VPN, for accounts using password authentication, the VPN Gateway must use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. For digital signature verification, SHA-1 is allowed for legacy-use. For all other hash function applications (e.g., HMAC, KDFs, RBG, password hashing, checksum integrity checks), the use of SHA-1 is acceptable, but discouraged in DoD. 

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.'
  desc 'check', 'For accounts using password authentication, verify the VPN Gateway uses FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.

For accounts using password authentication, if the VPN Gateway does not use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process, this is a finding.'
  desc 'fix', 'For accounts using password authentication, configure the VPN Gateway to use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7507r378362_chk'
  tag severity: 'medium'
  tag gid: 'V-207247'
  tag rid: 'SV-207247r608988_rule'
  tag stig_id: 'SRG-NET-000400-VPN-001940'
  tag gtitle: 'SRG-NET-000400'
  tag fix_id: 'F-7507r378363_fix'
  tag 'documentable'
  tag legacy: ['V-97189', 'SV-106327']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
