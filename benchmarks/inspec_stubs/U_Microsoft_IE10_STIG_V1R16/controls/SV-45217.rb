control 'SV-45217' do
  title 'Internet Explorer accelerator functionality must be disallowed.'
  desc 'The Internet Explorer Accelerator feature is for use with third-party applications and toolbars. This policy setting allows you to manage whether users can access accelerators. If you enable this policy setting, users cannot access accelerators. If you disable or do not configure this policy setting, users can access accelerators and install new accelerators.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Accelerators "Turn off Accelerators" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Activities 

Criteria: If the value NoActivities is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Accelerators "Turn off Accelerators" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42565r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34474'
  tag rid: 'SV-45217r1_rule'
  tag stig_id: 'DTBI1055'
  tag gtitle: 'DTBI1055 - Internet Explorer Accelerator'
  tag fix_id: 'F-38613r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
