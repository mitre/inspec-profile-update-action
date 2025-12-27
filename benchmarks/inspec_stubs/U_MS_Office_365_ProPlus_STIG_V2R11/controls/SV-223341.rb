control 'SV-223341' do
  title 'Files from unsafe locations must be opened in Excel in Protected View mode.'
  desc 'This policy setting lets you determine if files located in unsafe locations will open in Protected View. If you have not specified unsafe locations, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations.

If you enable this policy setting, files located in unsafe locations do not open in Protected View.

If you disable or do not configure this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Do not open files in unsafe locations in Protected View is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value DisableUnsafeLocationsInPV is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is REG_DWORD = 1, this is a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Do not open files in unsafe locations in Protected View to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25014r442242_chk'
  tag severity: 'medium'
  tag gid: 'V-223341'
  tag rid: 'SV-223341r879630_rule'
  tag stig_id: 'O365-EX-000032'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25002r442243_fix'
  tag 'documentable'
  tag legacy: ['SV-108861', 'V-99757']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
