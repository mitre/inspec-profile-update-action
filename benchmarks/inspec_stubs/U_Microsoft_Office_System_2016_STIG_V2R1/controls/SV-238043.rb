control 'SV-238043' do
  title 'The ability to send personal information to Office must be disabled.'
  desc 'This policy setting controls whether users can send personal information to Office. When users choose to send information Office 2016 applications automatically send information to Office. If you enable this policy setting, users will opt into sending personal information to Office.  If your organization has policies that govern the use of external resources, opting users into the program might cause them to violate these policies.  If you disable this policy setting, Office 2016 users cannot send personal information to Office.  If you do not configure this policy setting, the behavior is the equivalent of setting the policy to "Enabled".'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Privacy -> Trust Center -> "Send personal information" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\common

Criteria: If the value sendcustomerdata is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Privacy -> Trust Center -> "Send personal information" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41253r650694_chk'
  tag severity: 'medium'
  tag gid: 'V-238043'
  tag rid: 'SV-238043r650696_rule'
  tag stig_id: 'DTOO601'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-41212r650695_fix'
  tag 'documentable'
  tag legacy: ['SV-85523', 'V-70899']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
