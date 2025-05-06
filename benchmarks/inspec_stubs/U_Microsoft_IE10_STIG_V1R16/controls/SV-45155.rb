control 'SV-45155' do
  title 'First-Run prompt ability must be disallowed (Internet zone).'
  desc 'This policy setting controls the First Run response that users see on a zone-by-zone basis. When a user encounters a new control that has not previously run in Internet Explorer, they may be prompted to approve the control. This feature determines if the user gets the prompt or not. If you enable this policy setting, the Gold Bar prompt will be turned off in the corresponding zone. If you disable this policy setting, the Gold Bar prompt will be turned on in the corresponding zone. If you do not configure this policy setting, the first-run prompt is turned off by default.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Turn off first-run prompt" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1208 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Turn off first-run prompt" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42498r3_chk'
  tag severity: 'medium'
  tag gid: 'V-15525'
  tag rid: 'SV-45155r1_rule'
  tag stig_id: 'DTBI475'
  tag gtitle: 'DTBI475 - First-Run Opt-In - Internet'
  tag fix_id: 'F-38551r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
