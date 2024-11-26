control 'SV-223136' do
  title 'Cross-Site Scripting Filter must be enforced (Internet zone).'
  desc 'The Cross-Site Scripting Filter is designed to prevent users from becoming victims of unintentional information disclosure. This setting controls if the Cross-Site Scripting (XSS) Filter detects and prevents cross-site script injection into websites in this zone. If you enable this policy setting, the XSS Filter will be enabled for sites in this zone, and the XSS Filter will attempt to block cross-site script injections. If you disable this policy setting, the XSS Filter will be disabled for sites in this zone, and Internet Explorer will permit cross-site script injections.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Turn on Cross-Site Scripting Filter' must be 'Enabled', and 'Enable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1409" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24809r428958_chk'
  tag severity: 'medium'
  tag gid: 'V-223136'
  tag rid: 'SV-223136r428960_rule'
  tag stig_id: 'DTBI840-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24797r428959_fix'
  tag 'documentable'
  tag legacy: ['SV-59745', 'V-46879']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
