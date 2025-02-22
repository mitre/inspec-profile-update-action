control 'SV-205509' do
  title 'The Mainframe Product must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

Applications using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is configured to be FIPS 140 compliant, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to be FIPS 140 compliant.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5775r299760_chk'
  tag severity: 'medium'
  tag gid: 'V-205509'
  tag rid: 'SV-205509r397606_rule'
  tag stig_id: 'SRG-APP-000179-MFP-000247'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-5775r299761_fix'
  tag 'documentable'
  tag legacy: ['SV-82897', 'V-68407']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
