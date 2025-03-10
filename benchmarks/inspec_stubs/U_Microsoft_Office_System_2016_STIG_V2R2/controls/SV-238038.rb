control 'SV-238038' do
  title 'Office Presentation Service must be removed as an option for presenting PowerPoint and Word online.'
  desc 'This policy setting allows you to remove Office Presentation Service from the list of online presentation services in PowerPoint and Word. This list appears when a user selects Present Online from the Share tab in Backstage view and in the ribbon in PowerPoint. If you enable this policy setting, Office Presentation Service is not shown as an option for presenting online. If you disable or do not configure this policy setting, users can select Office Presentation Service to present their PowerPoint or Word file to other users online.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Present Online -> "Remove Office Presentation Service from the list of online presentation services in PowerPoint and Word" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\common\\broadcast 

Criteria: If the value disabledefaultservice is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Present Online -> "Remove Office Presentation Service from the list of online presentation services in PowerPoint and Word" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41248r650679_chk'
  tag severity: 'medium'
  tag gid: 'V-238038'
  tag rid: 'SV-238038r650681_rule'
  tag stig_id: 'DTOO408'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-41207r650680_fix'
  tag 'documentable'
  tag legacy: ['SV-85513', 'V-70889']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
