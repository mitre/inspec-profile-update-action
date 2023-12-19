control 'SV-59439' do
  title 'The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone).'
  desc 'Unsigned code is potentially harmful, especially when coming from an untrusted zone. ActiveX controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. They must also be digitally signed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download unsigned ActiveX controls' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1004" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download unsigned ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49741r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46575'
  tag rid: 'SV-59439r1_rule'
  tag stig_id: 'DTBI113-IE11'
  tag gtitle: 'DTBI113-IE11-Download unsigned ActiveX - Restricted Sites'
  tag fix_id: 'F-50345r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
