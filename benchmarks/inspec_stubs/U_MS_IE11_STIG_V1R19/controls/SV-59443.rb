control 'SV-59443' do
  title 'ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether ActiveX controls and plug-ins can be run on pages from the specified zone. ActiveX controls not marked as safe should not be executed. If you enable this policy setting, controls and plug-ins can run without user intervention. If you disable this policy setting, controls and plug-ins are prevented from running.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Run ActiveX controls and plugins' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1200" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Run ActiveX controls and plugins' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49745r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46579'
  tag rid: 'SV-59443r1_rule'
  tag stig_id: 'DTBI115-IE11'
  tag gtitle: 'DTBI115-IE11-ActiveX control and plugins - Restricted Sites'
  tag fix_id: 'F-50349r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001687']
  tag nist: ['SC-18 (2)']
end
