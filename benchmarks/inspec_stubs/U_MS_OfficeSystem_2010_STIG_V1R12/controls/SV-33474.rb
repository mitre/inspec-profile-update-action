control 'SV-33474' do
  title 'External Signature Services Menu for Office must be suppressed.'
  desc 'Users can select Add Signature Services (from the Signature Line drop-down menu on the Insert tab of the Ribbon in Excel 2010, PowerPoint 2010, and Word 2010) to see a list of signature service providers on the Microsoft Office Web site. If your organization has policies that govern the use of external resources such as signature providers or Office Marketplace, allowing users to access the Add Signature Services menu item might enable them to violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing “Suppress external signature services menu item” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\signatures

Criteria: If the value SuppressExtSigningSvcs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Signing “Suppress external signature services menu item” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33957r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17805'
  tag rid: 'SV-33474r1_rule'
  tag stig_id: 'DTOO204 - Office System'
  tag gtitle: 'DTOO204 - External Signature Services menu'
  tag fix_id: 'F-29646r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
