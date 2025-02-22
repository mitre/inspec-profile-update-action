control 'SV-223334' do
  title 'File validation in Excel must be enabled.'
  desc 'This policy setting allows you turn off the file validation feature.

If you enable this policy setting, file validation will be turned off.

If you disable or do not configure this policy setting, file validation will be turned on. Office Binary Documents (97-2003) are checked to see if they conform against the file format schema before they are opened.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Turn off file validation is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\filevalidation

If the value for enableonload is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Turn off file validation to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25007r442221_chk'
  tag severity: 'medium'
  tag gid: 'V-223334'
  tag rid: 'SV-223334r508019_rule'
  tag stig_id: 'O365-EX-000025'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-24995r442222_fix'
  tag 'documentable'
  tag legacy: ['SV-108847', 'V-99743']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
