control 'SV-40764' do
  title 'ActiveX opt-in prompt must be disallowed.'
  desc 'This policy setting allows you to turn off the ActiveX opt-in prompt. The ActiveX opt-in prevents Web sites from loading any COM object without prior approval.  If a page attempts to load a COM object that Internet Explorer has not used before, an Information bar will appear asking the user for approval.  If you enable this policy setting, the ActiveX opt-in prompt will not appear.  Internet Explorer does not ask the user for permission to load a control, and will load the ActiveX if it passes all other internal security checks.  If you disable or do not configure this policy setting the ActiveX opt-in prompt will appear.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off ActiveX opt-in prompt" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext 

Criteria: If the value NoFirsttimeprompt is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off ActiveX opt-in prompt" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39509r2_chk'
  tag severity: 'medium'
  tag gid: 'V-30778'
  tag rid: 'SV-40764r1_rule'
  tag stig_id: 'DTBI805'
  tag gtitle: 'DTBI805 - Opt-In Prompts for ActiveX'
  tag fix_id: 'F-34625r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
