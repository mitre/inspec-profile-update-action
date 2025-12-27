control 'SV-40587' do
  title 'The Download unsigned ActiveX controls property must be disallowed (Restricted Site zone).'
  desc 'Unsigned code is potentially harmful, especially when coming from an untrusted zone.  ActiveX controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites and they must be digitally signed.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Download unsigned ActiveX controls" must be “Enabled” and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1004 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Download unsigned ActiveX controls" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39342r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6290'
  tag rid: 'SV-40587r1_rule'
  tag stig_id: 'DTBI113'
  tag gtitle: 'DTBI113 - Download unsigned ActiveX - Restricted'
  tag fix_id: 'F-34451r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
