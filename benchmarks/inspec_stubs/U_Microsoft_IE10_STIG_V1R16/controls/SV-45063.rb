control 'SV-45063' do
  title 'Ability to install new versions of Internet Explorer automatically must be disallowed.'
  desc 'This policy setting configures Internet Explorer to automatically install new versions of Internet Explorer when they are available. If you enable this policy setting, automatic upgrade of Internet Explorer will be turned on. If you disable this policy setting, automatic upgrade of Internet Explorer will be turned off. If you do not configure this policy, users can turn on or off automatic updates.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer "Install new versions of Internet Explorer automatically" must be "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value EnableAutoUpgrade is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer "Install new versions of Internet Explorer automatically" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42436r1_chk'
  tag severity: 'medium'
  tag gid: 'V-34425'
  tag rid: 'SV-45063r1_rule'
  tag stig_id: 'DTBI980'
  tag gtitle: 'DTBI980 - Internet Explorer Automatic Updates'
  tag fix_id: 'F-38471r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
