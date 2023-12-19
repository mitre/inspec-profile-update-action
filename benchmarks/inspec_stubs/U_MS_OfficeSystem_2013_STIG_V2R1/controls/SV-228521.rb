control 'SV-228521' do
  title 'External Signature Services Menu for Office must be suppressed.'
  desc 'Users can select Add Signature Services (from the Signature Line drop-down menu on the Insert tab of the Ribbon in Excel 2013, PowerPoint 2013, and Word 2013) to see a list of signature service providers on the Microsoft Office website. If an organization has policies that govern the use of external resources such as signature providers or Office Marketplace, allowing users to access the Add Signature Services menu item might enable them to violate those policies.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Signing "Suppress external signature services menu item" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\signatures

Criteria: If the value 'SuppressExtSigningSvcs' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Signing "Suppress external signature services menu item" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30754r498841_chk'
  tag severity: 'medium'
  tag gid: 'V-228521'
  tag rid: 'SV-228521r508020_rule'
  tag stig_id: 'DTOO204'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30739r498842_fix'
  tag 'documentable'
  tag legacy: ['V-17805', 'SV-52752']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
