control 'SV-223403' do
  title 'Files located in unsafe locations must be opened in Protected view in Word.'
  desc 'This policy setting lets you determine if files located in unsafe locations will open in Protected View. If you have not specified unsafe locations, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations.

If you enable this policy setting, files located in unsafe locations do not open in Protected View.

If you disable or do not configure this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Do not open files in unsafe locations in Protected View is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security\\protectedview.

If the value for disableunsafelocationsinpv is REG_DWORD = 0, this is not a finding. If the value does not exist, this is not a finding.

If the value is REG_DWORD = 1, this is a finding.'
  desc 'fix', 'Set the policy setting, User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Do not open files in unsafe locations in Protected View to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25076r442428_chk'
  tag severity: 'medium'
  tag gid: 'V-223403'
  tag rid: 'SV-223403r879628_rule'
  tag stig_id: 'O365-WD-000004'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25064r442429_fix'
  tag 'documentable'
  tag legacy: ['SV-108987', 'V-99883']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
