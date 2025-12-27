control 'SV-87491' do
  title 'Macros must be blocked from running in Office 2013 files from the Internet.'
  desc %q(This policy setting allows you to block macros from running in Office files that come from the Internet. If you enable this policy setting, macros are blocked from running, even if "Enable all macros" is selected in the Macro Settings section of the Trust Center. Also, instead of having the choice to "Enable Content", users will receive a notification that macros are blocked from running. If the Office file is saved to a trusted location or was previously trusted by the user, macros will be allowed to run. If you disable or don't configure this policy setting, the settings configured in the Macro Settings section of the Trust Center determine whether macros run in Office files that come from the Internet.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2013 >> PowerPoint Options >> Security >> Trust Center "Block macros from running in Office files from the Internet" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security

Criteria: If the value blockcontentexecutionfrominternet is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2013 >> PowerPoint Options >> Security >> Trust Center "Block macros from running in Office files from the Internet" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-72967r2_chk'
  tag severity: 'medium'
  tag gid: 'V-72839'
  tag rid: 'SV-87491r1_rule'
  tag stig_id: 'DTOO600'
  tag gtitle: 'DTOO600 - Macros must be blocked from running in Office 2013 files from the Internet.'
  tag fix_id: 'F-79279r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
