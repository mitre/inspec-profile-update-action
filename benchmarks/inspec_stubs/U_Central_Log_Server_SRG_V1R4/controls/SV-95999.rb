control 'SV-95999' do
  title 'For accounts using password authentication, the Central Log Server must use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

This requirement applies to all accounts, including authentication server; Authorization, Authentication, and Accounting (AAA); and local accounts such as the root account and the account of last resort.

This requirement only applies to components where this is specific to the function of the device (e.g., TLS VPN or ALG). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.

If the Central Log Server is not configured to use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to  use FIPS-validated SHA-1 or later protocol to protect the integrity of the password authentication process.'
  impact 0.7
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80985r1_chk'
  tag severity: 'high'
  tag gid: 'V-81285'
  tag rid: 'SV-95999r1_rule'
  tag stig_id: 'SRG-APP-000172-AU-002550'
  tag gtitle: 'SRG-APP-000172-AU-002550'
  tag fix_id: 'F-88067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
