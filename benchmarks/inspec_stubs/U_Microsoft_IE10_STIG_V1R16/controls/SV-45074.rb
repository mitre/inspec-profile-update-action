control 'SV-45074' do
  title 'ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows management of whether ActiveX controls marked safe for scripting can interact with a script. If you enable this policy setting, script interaction can occur automatically without user intervention. ActiveX controls not marked as safe for scripting should not be executed. Although this is not a complete security measure for a control to be marked safe for scripting, if a control is not marked safe, it should not be initialized and executed.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Script ActiveX controls marked safe for scripting" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1405 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Script ActiveX controls marked safe for scripting" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42446r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6293'
  tag rid: 'SV-45074r1_rule'
  tag stig_id: 'DTBI116'
  tag gtitle: 'DTBI116 - ActiveX control marked safe - Restricted'
  tag fix_id: 'F-38481r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
