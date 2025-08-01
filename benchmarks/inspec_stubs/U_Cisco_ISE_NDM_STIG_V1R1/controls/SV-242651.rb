control 'SV-242651' do
  title 'For accounts using password authentication, the Cisco ISE must use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. 

This requirement applies to all accounts, including authentication server, AAA, and local accounts such as the root account and the account of last resort.

This requirement only applies to components where this is specific to the function of the device (e.g., Transport Layer Security [TLS] Virtual Private Network [VPN] or Application Layer Gateway [ALG]). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45926r714261_chk'
  tag severity: 'high'
  tag gid: 'V-242651'
  tag rid: 'SV-242651r714263_rule'
  tag stig_id: 'CSCO-NM-000460'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-45883r714262_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
