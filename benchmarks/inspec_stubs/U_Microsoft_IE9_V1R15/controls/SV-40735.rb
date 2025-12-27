control 'SV-40735' do
  title 'Cross-Site Scripting (XSS) Filter must be enforced (Internet zone).'
  desc 'The Cross-Site Scripting (XSS) Filter is designed to prevent users from becoming victims of unintentional information disclosure. This setting controls if the Cross-Site Scripting (XSS) Filter detects and prevents cross-site script injection into web sites in this zone. If you enable this policy setting, the XSS Filter will be enabled for sites in this zone, and the XSS Filter will attempt to block cross-site script injections. If you disable this policy setting, the XSS Filter will be disabled for sites in this zone, and Internet Explorer will permit cross-site script injections.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> “Turn on Cross-Site Scripting (XSS) Filter” must be “Enabled” and “Enable” selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1409 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> “Turn on Cross-Site Scripting (XSS) Filter” to “Enabled” and select “Enable” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39478r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22156'
  tag rid: 'SV-40735r1_rule'
  tag stig_id: 'DTBI840'
  tag gtitle: 'DTBI840 - Cross-Site Scripting Filter - Internet'
  tag fix_id: 'F-34594r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
