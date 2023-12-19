control 'SV-205577' do
  title 'The Mainframe Product must conform to FICAM-issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

This requirement addresses open identity management standards.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to conform to FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5843r299958_chk'
  tag severity: 'medium'
  tag gid: 'V-205577'
  tag rid: 'SV-205577r851343_rule'
  tag stig_id: 'SRG-APP-000405-MFP-000252'
  tag gtitle: 'SRG-APP-000405'
  tag fix_id: 'F-5843r299959_fix'
  tag 'documentable'
  tag legacy: ['SV-82907', 'V-68417']
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
