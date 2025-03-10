control 'SV-45133' do
  title 'Cross-Site Scripting (XSS) Filter property must be enforced (Restricted Sites zone).'
  desc 'The Cross-Site Scripting (XSS) Filter is designed to prevent users from becoming victims of unintentional information disclosure. This setting controls if the Cross-Site Scripting (XSS) Filter detects and prevents cross-site script injection into websites in this zone. If you enable this policy setting, the XSS Filter will be enabled for sites in this zone, and the XSS Filter will attempt to block cross-site script injections. If you disable this policy setting, the XSS Filter will be disabled for sites in this zone, and Internet Explorer will permit cross-site script injections.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Turn on Cross-Site Scripting (XSS) Filter" must be "Enabled", and "Enable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1409 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Turn on Cross-Site Scripting (XSS) Filter" to "Enabled", and select "Enable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42478r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22161'
  tag rid: 'SV-45133r1_rule'
  tag stig_id: 'DTBI890'
  tag gtitle: 'DTBI890 - Cross-Site Scripting Filter - Restricted'
  tag fix_id: 'F-38529r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
