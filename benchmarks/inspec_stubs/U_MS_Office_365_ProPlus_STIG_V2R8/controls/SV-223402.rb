control 'SV-223402' do
  title 'Files downloaded from the Internet must be opened in Protected view in Word.'
  desc 'This policy setting allows you to determine if files downloaded from the Internet zone open in Protected View.

If you enable this policy setting, files downloaded from the Internet zone do not open in Protected View.

If you disable or do not configure this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'Verify the policy setting, User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Do not open files from the Internet zone in Protected View is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security\\protectedview

If the value for disableinternetfilesinpv is REG_DWORD = 0, this is not a finding. If the value does not exist, this is not a finding.

If the value is REG_DWORD = 1, this is a finding.'
  desc 'fix', 'Set the policy setting, User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security >> Trust Center >> Protected View >> Do not open files from the Internet zone in Protected View to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25075r442425_chk'
  tag severity: 'medium'
  tag gid: 'V-223402'
  tag rid: 'SV-223402r879628_rule'
  tag stig_id: 'O365-WD-000003'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25063r442426_fix'
  tag 'documentable'
  tag legacy: ['SV-108985', 'V-99881']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
