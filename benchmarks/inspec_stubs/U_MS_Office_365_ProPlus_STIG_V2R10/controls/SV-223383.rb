control 'SV-223383' do
  title 'Macros from the Internet must be blocked from running in PowerPoint.'
  desc 'This policy setting allows you to block macros from running in Office files that come from the Internet. If you enable this policy setting, macros are blocked from running, even if "Enable all macros" is selected in the Macro Settings section of the Trust Center. Also, instead of having the choice to "Enable Content", users will receive a notification that macros are blocked from running. 

If the Office file is saved to a trusted location or was previously trusted by the user, macros will be allowed to run. If you disable or do not configure this policy setting, the settings configured in the Macro Settings section of the Trust Center determine whether macros run in Office files that come from the Internet.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center "Block macros from running in Office files from the Internet" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\powerpoint\\security

If the value blockcontentexecutionfrominternet is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center "Block macros from running in Office files from the Internet" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25056r442368_chk'
  tag severity: 'medium'
  tag gid: 'V-223383'
  tag rid: 'SV-223383r879630_rule'
  tag stig_id: 'O365-PT-000007'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25044r442369_fix'
  tag 'documentable'
  tag legacy: ['SV-108941', 'V-99837']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
