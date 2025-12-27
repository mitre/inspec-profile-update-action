control 'SV-59445' do
  title 'ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows management of whether ActiveX controls marked safe for scripting can interact with a script. If you enable this policy setting, script interaction can occur automatically without user intervention. ActiveX controls not marked as safe for scripting should not be executed. Although this is not a complete security measure for a control to be marked safe for scripting, if a control is not marked safe, it should not be initialized and executed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Script ActiveX controls marked safe for scripting' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1405" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Script ActiveX controls marked safe for scripting' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49747r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46581'
  tag rid: 'SV-59445r1_rule'
  tag stig_id: 'DTBI116-IE11'
  tag gtitle: 'DTBI116-IE11-ActiveX controls marked safe - Restricted Sites'
  tag fix_id: 'F-50351r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
