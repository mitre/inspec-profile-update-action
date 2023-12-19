control 'SV-59565' do
  title 'Allow binary and script behaviors must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage dynamic binary and script behaviors of components that encapsulate specific functionality for HTML elements, to which they were attached. If you enable this policy setting, binary and script behaviors are available.   If you select "Administrator approved" in the drop-down box, only the behaviors listed in the Admin-approved Behaviors under Binary Behaviors Security Restriction policy are available.    If you disable this policy setting, binary and script behaviors are not available unless applications have implemented a custom security manager. If you do not configure this policy setting, binary and script behaviors are available.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow binary and script behaviors' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2000" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow binary and script behaviors' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49847r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46701'
  tag rid: 'SV-59565r1_rule'
  tag stig_id: 'DTBI575-IE11'
  tag gtitle: 'DTBI575-IE11-Binary and script behaviors - Restricted Sites'
  tag fix_id: 'F-50461r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
