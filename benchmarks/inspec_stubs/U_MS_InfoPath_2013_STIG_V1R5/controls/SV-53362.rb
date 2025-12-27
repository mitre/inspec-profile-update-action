control 'SV-53362' do
  title 'Opening behavior for Email forms containing code or scripts must be controlled.'
  desc "InfoPath notifies and prompts users before opening InfoPath email forms that contain code or script. If this restriction is relaxed, InfoPath will open email forms that contain code or script without prompting users, which could allow malicious code to run on the users' computers."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Control behavior when opening InfoPath e-mail forms containing code or script" must be set to "Enabled (Prompt before running)".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value EMailFormsRunCodeAndScript is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> InfoPath e-mail forms "Control behavior when opening InfoPath e-mail forms containing code or script" to "Enabled (Prompt before running)".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47622r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17580'
  tag rid: 'SV-53362r1_rule'
  tag stig_id: 'DTOO167'
  tag gtitle: 'DTOO167 - Forms Opening behavior - EMail /w code'
  tag fix_id: 'F-46290r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
