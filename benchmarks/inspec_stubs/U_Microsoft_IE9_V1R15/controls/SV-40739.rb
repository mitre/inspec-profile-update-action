control 'SV-40739' do
  title 'ActiveX controls without prompt property must be used in approved domains only (Restricted Site zone).'
  desc "This policy setting controls whether or not the user is prompted to allow ActiveX controls to run on web sites other than the web site that installed the ActiveX control. If the user were to disable the setting for the zone, malicious ActiveX controls could be executed without the user's knowledge. Disabling this setting would allow the possibility for malicious ActiveX controls to be executed from non-approved domains within this zone without the user's knowledge. Enabling this setting enforces the default value and prohibits the user from changing the value. Web sites should be moved into another zone if permissions need to be changed."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Only allow approved domains to use ActiveX controls without prompt” must be “Enabled” and “Enable” selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 120b is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> “Only allow approved domains to use ActiveX controls without prompt” to “Enabled” and select “Enable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39486r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22160'
  tag rid: 'SV-40739r1_rule'
  tag stig_id: 'DTBI880'
  tag gtitle: 'DTBI880 - ActiveX controls no prompt - Restricted'
  tag fix_id: 'F-34603r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
