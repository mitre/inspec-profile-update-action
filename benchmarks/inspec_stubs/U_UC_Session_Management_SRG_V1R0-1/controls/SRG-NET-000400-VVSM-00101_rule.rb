control 'SRG-NET-000400-VVSM-00101_rule' do
  title 'For accounts using password authentication, the Unified Communications Session Manager must be configured to use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Use of passwords for authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DOD systems should not be configured to use SHA-2 for integrity of remote access sessions.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

Pre-shared key cipher suites may only be used in networks where both the client and server belong to the same organization. Cipher suites using preshared keys must not be used with TLS 1.0 or 1.1 and must not be used with TLS 1.2 when a government client or server communicates with non-government systems. This requirement applies to all accounts, including authentication server, AAA, and local accounts such as the root account and the account of last resort.

This requirement only applies to components where this is specific to the function of the device (e.g., Transport Layer Security [TLS] Virtual Private Network [VPN] or Application Layer Gateway [ALG]). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the Unified Communications Session Manager, for accounts using password authentication, is configured to SHA-2 or greater to protect the integrity of the password authentication process.

If the Unified Communications Session Manager is not configured to use SHA-2 or greater to protect the password authentication process, this is a finding.'
  desc 'fix', 'For accounts using password authentication, configure the Unified Communications Session Manager to use SHA-2 or greater to protect the integrity of the password authentication process.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000400-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000400-VVSM-00101'
  tag rid: 'SRG-NET-000400-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000400-VVSM-00101'
  tag gtitle: 'SRG-NET-000400-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000400-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
