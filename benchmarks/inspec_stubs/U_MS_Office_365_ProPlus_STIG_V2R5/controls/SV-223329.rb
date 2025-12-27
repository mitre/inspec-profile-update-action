control 'SV-223329' do
  title 'Loading of pictures from Web pages not created in Excel must be disabled.'
  desc 'This policy setting controls whether Excel loads graphics when opening Web pages that were not created in Excel. It configures the "Load pictures from Web pages not created in Excel" option under the File tab >> Options >> Advanced >> General >> Web Options... >> General tab.

If you enable or do not configure this policy setting, Excel loads any graphics that are included in the pages, regardless of whether they were originally created in Excel.

If you disable this policy setting, Excel will not load any pictures from Web pages that were not created in Excel.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Advanced >> Web Options... >> General.

Load pictures from Web pages not created in Excel is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\internet

If the value for donotloadpictures is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Advanced >> Web Options... >> General >> Load pictures from Web pages not created in Excel to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25002r442206_chk'
  tag severity: 'medium'
  tag gid: 'V-223329'
  tag rid: 'SV-223329r508019_rule'
  tag stig_id: 'O365-EX-000020'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-24990r442207_fix'
  tag 'documentable'
  tag legacy: ['SV-108837', 'V-99733']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
