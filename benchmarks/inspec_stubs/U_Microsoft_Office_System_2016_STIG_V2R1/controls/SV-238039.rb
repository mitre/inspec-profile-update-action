control 'SV-238039' do
  title 'The ability to create an online presentation programmatically must be disabled.'
  desc 'This policy setting allows you to restrict the ability to create an online presentation programmatically in PowerPoint and Word. If you enable this policy setting, an online presentation cannot be created programmatically. If you disable or do not configure this policy setting, an online presentation can be created programmatically.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Present Online -> "Restrict programmatic access for creating online presentations in PowerPoint and Word" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\common\\broadcast 

Criteria: If the value disableprogrammaticaccess is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Present Online -> "Restrict programmatic access for creating online presentations in PowerPoint and Word" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41249r650682_chk'
  tag severity: 'medium'
  tag gid: 'V-238039'
  tag rid: 'SV-238039r650684_rule'
  tag stig_id: 'DTOO409'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-41208r650683_fix'
  tag 'documentable'
  tag legacy: ['SV-85515', 'V-70891']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
