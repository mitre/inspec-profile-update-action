control 'SV-207247' do
  title 'For accounts using password authentication, the site-to-site VPN Gateway must use SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-2 for integrity of remote access sessions.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

Pre-shared key cipher suites may only be used in networks where both the client and server belong to the same organization. Cipher suites using pre-shared keys shall not be used with TLS 1.0 or 1.1 and shall not be used with TLS 1.2 when a Government client or server communicates with non-government systems.'
  desc 'check', 'For accounts using password authentication, verify the VPN Gateway uses SHA-2 or later protocol to protect the integrity of the password authentication process.

For accounts using password authentication, if the VPN Gateway does not use SHA-2 or later protocol to protect the integrity of the password authentication process, this is a finding.'
  desc 'fix', 'For accounts using password authentication, configure the VPN Gateway to use SHA-2 or later protocol to protect the integrity of the password authentication process.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7507r803433_chk'
  tag severity: 'medium'
  tag gid: 'V-207247'
  tag rid: 'SV-207247r803435_rule'
  tag stig_id: 'SRG-NET-000400-VPN-001940'
  tag gtitle: 'SRG-NET-000400'
  tag fix_id: 'F-7507r803434_fix'
  tag 'documentable'
  tag legacy: ['V-97189', 'SV-106327']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
