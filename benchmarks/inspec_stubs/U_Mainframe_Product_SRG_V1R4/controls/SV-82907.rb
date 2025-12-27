control 'SV-82907' do
  title 'The Mainframe Product must conform to FICAM-issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

This requirement addresses open identity management standards.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations.

If the Mainframe Product is not configured to conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to conform to FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68417'
  tag rid: 'SV-82907r1_rule'
  tag stig_id: 'SRG-APP-000405-MFP-000252'
  tag gtitle: 'SRG-APP-000405-MFP-000252'
  tag fix_id: 'F-74533r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
