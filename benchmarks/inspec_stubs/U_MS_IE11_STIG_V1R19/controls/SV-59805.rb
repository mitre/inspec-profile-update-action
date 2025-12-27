control 'SV-59805' do
  title 'Status bar updates via script must be disallowed (Restricted Sites zone).'
  desc 'A script running in the zone could cause false information to be displayed on the status bar, which could confuse the user and cause an undesirable action. This policy setting allows you to manage whether script is allowed to update the status bar within the zone. If you enable this policy setting, script is allowed to update the status bar. If you disable this policy setting, script is not allowed to update the status bar. If you do not configure this policy setting, status bar updates via scripts will be disabled.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 'Allow updates to status bar via script' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2103" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 'Allow updates to status bar via script' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49963r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46939'
  tag rid: 'SV-59805r1_rule'
  tag stig_id: 'DTBI950-IE11'
  tag gtitle: 'DTBI950-IE11-Status bar updates via script - Restricted Sites'
  tag fix_id: 'F-50671r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
