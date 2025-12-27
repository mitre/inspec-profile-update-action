control 'SV-223340' do
  title 'Files from Internet zone must be opened in Excel in Protected View mode.'
  desc 'This policy setting allows you to determine if files downloaded from the Internet zone open in Protected View.

If you enable this policy setting, files downloaded from the Internet zone do not open in Protected View.

If you disable or do not configure this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Do not open files from the Internet zone in Protected View is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding. 

If the value does not exist, this is not a finding.

If the value is REG_DWORD = 1, this is a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Do not open files from the Internet zone in Protected View to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25013r442239_chk'
  tag severity: 'medium'
  tag gid: 'V-223340'
  tag rid: 'SV-223340r508019_rule'
  tag stig_id: 'O365-EX-000031'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25001r442240_fix'
  tag 'documentable'
  tag legacy: ['SV-108859', 'V-99755']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
