control 'SV-45306' do
  title 'Security Warning for unsafe files must be set to prompt (Internet zone).'
  desc 'This policy setting controls whether or not the "Open File - Security Warning" message appears when the user tries to open executable files or other potentially unsafe files (from an intranet file shared by using Windows Explorer, for example). If you enable this policy setting and set the drop-down box to Enable, these files open without a security warning. If you set the drop-down box to Prompt, a security warning appears before the files open. If you disable this policy these files do not open. If you do not configure this policy setting, the user can configure how the computer handles these files.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Show security warning for potentially unsafe files" must be "Enabled", and "Prompt" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1806 is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Show security warning for potentially unsafe files" to "Enabled", and select "Prompt" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42654r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22154'
  tag rid: 'SV-45306r1_rule'
  tag stig_id: 'DTBI820'
  tag gtitle: 'DTBI820 - Programs and unsafe files - Internet'
  tag fix_id: 'F-38702r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
