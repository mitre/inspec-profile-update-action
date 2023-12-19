control 'SV-59437' do
  title 'The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).'
  desc 'ActiveX controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download signed ActiveX controls' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1001" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49739r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46573'
  tag rid: 'SV-59437r1_rule'
  tag stig_id: 'DTBI112-IE11'
  tag gtitle: 'DTBI112-IE11-Download signed ActiveX - Restricted Sites'
  tag fix_id: 'F-50343r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
