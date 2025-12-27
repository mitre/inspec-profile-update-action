control 'SV-40732' do
  title 'Launching programs and unsafe files property must be set to prompt (Internet zone).'
  desc 'This policy setting controls whether or not the “Open File – Security Warning” prompt is shown when launching executables or other unsafe files. If you do not configure this policy setting, users can configure the prompt behavior. By default, execution is blocked in the Restricted Zone, enabled in the Intranet and Local Computer Zone, and set to prompt in the Internet and Trusted Zones.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> “Launching programs and unsafe files” must be “Enabled” and “Prompt” selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1806 is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> “Launching programs and unsafe files” to “Enabled” and select “Prompt” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39474r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22154'
  tag rid: 'SV-40732r1_rule'
  tag stig_id: 'DTBI820'
  tag gtitle: 'DTBI820 - Programs and unsafe files - Internet'
  tag fix_id: 'F-34592r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
