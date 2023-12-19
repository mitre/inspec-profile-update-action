control 'SV-223051' do
  title 'The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).'
  desc 'ActiveX controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download signed ActiveX controls' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1001" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24724r428703_chk'
  tag severity: 'medium'
  tag gid: 'V-223051'
  tag rid: 'SV-223051r428705_rule'
  tag stig_id: 'DTBI112-IE11'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-24712r428704_fix'
  tag 'documentable'
  tag legacy: ['SV-59437', 'V-46573']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
