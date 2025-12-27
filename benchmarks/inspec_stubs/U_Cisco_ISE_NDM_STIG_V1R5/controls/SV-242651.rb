control 'SV-242651' do
  title 'For accounts using password authentication, the Cisco ISE must use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The information system must specify the hash algorithm used for authenticating passwords. Implementation of this requirement requires configuration of FIPS-approved cipher block algorithm and block cipher modes for encryption.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DOD systems should not be configured to use SHA-1 for integrity of remote access sessions. 

This requirement applies to all accounts, including authentication server, AAA, and local accounts such as the root account and the account of last resort.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If FIPS Mode is enabled, this is not a finding.

If FIPS mode is not configured, but the Cisco ISE is configured using an alternative manual method to configure the password authentication process to use a FIPS 140-2/140-3 validated SHA-2 (or greater), this can be lowered to a CAT 2 finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure FIPS 140-2/140-3 algorithms are used in all security functions requiring cryptographic functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.

Note: Configuring FIPS mode is the required DOD configuration. However, this requirement can be lowered to a CAT 2 if the alternative manual configuration is used to configure the password authentication process to use a FIPS 140-2/140-3 validated SHA-2 (or greater).'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45926r916079_chk'
  tag severity: 'high'
  tag gid: 'V-242651'
  tag rid: 'SV-242651r916317_rule'
  tag stig_id: 'CSCO-NM-000460'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-45883r916317_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
