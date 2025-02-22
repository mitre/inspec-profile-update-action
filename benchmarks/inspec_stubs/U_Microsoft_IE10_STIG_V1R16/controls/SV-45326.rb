control 'SV-45326' do
  title 'The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).'
  desc 'ActiveX controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Download signed ActiveX controls" must be "Enabled", and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1001 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Download signed ActiveX controls" to "Enabled", and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6289'
  tag rid: 'SV-45326r1_rule'
  tag stig_id: 'DTBI112'
  tag gtitle: 'DTBI112-Download signed ActiveX - Restricted Sites'
  tag fix_id: 'F-38723r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
