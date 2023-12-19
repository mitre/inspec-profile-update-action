control 'SV-223143' do
  title 'Status bar updates via script must be disallowed (Internet zone).'
  desc 'This policy setting allows you to manage whether script is allowed to update the status bar within the zone. A script running in the zone could cause false information to be displayed on the status bar, which could confuse the user and cause them to perform an undesirable action. If you enable this policy setting, script is allowed to update the status bar. If you disable this policy setting, script is not allowed to update the status bar. If you do not configure this policy setting, status bar updates via scripts will be disabled.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Allow updates to status bar via script' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2103" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone 'Allow updates to status bar via script' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24816r428979_chk'
  tag severity: 'medium'
  tag gid: 'V-223143'
  tag rid: 'SV-223143r428981_rule'
  tag stig_id: 'DTBI910-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24804r428980_fix'
  tag 'documentable'
  tag legacy: ['SV-59769', 'V-46903']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
