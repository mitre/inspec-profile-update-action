control 'SV-45072' do
  title 'ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether ActiveX controls and plug-ins can be run on pages from the specified zone. ActiveX controls not marked as safe should not be executed. If you enable this policy setting, controls and plug-ins can run without user intervention. If you disable this policy setting, controls and plug-ins are prevented from running.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run ActiveX controls and plugins" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1200 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Run ActiveX controls and plugins" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42444r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6292'
  tag rid: 'SV-45072r1_rule'
  tag stig_id: 'DTBI115'
  tag gtitle: 'DTBI115 - ActiveX control and plugins - Restricted'
  tag fix_id: 'F-38479r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
