control 'SV-223385' do
  title 'Files downloaded from the Internet must be opened in Protected view in PowerPoint.'
  desc 'This policy setting allows you to determine if files downloaded from the Internet zone open in Protected View. If you enable this policy setting, files downloaded from the Internet zone do not open in Protected View. If you disable or do not configure this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Do not open files from the Internet zone in Protected View" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\protectedview

If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Do not open files from the Internet zone in Protected View" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25058r442374_chk'
  tag severity: 'medium'
  tag gid: 'V-223385'
  tag rid: 'SV-223385r508019_rule'
  tag stig_id: 'O365-PT-000009'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25046r442375_fix'
  tag 'documentable'
  tag legacy: ['SV-108945', 'V-99841']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
