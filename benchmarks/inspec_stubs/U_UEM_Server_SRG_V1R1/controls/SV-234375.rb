control 'SV-234375' do
  title 'For UEM server using password authentication, the network element must use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems must not be configured to use SHA-1 for integrity of remote access sessions. 

This requirement applies to all accounts, including authentication server; Authorization, Authentication, and Accounting (AAA); and local accounts such as the root account and the account of last resort.

This requirement only applies to components where this is specific to the function of the device (e.g., TLS VPN or ALG). This does not apply to authentication for the purpose of configuring the device itself (management). 

Satisfies:FIA_ENR_EXT.1.1, FCS_COP.1.1(2) Refinement'
  desc 'check', 'For UEM server using password authentication, verify the network element uses FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.

If UEM server using password authentication but the network element does not use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process, this is a finding.'
  desc 'fix', 'For a UEM server using password authentication, configure the network element to use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37560r614135_chk'
  tag severity: 'high'
  tag gid: 'V-234375'
  tag rid: 'SV-234375r617355_rule'
  tag stig_id: 'SRG-APP-000172-UEM-000102'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-37525r614136_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
