control 'SV-40652' do
  title 'Protected Mode must be enforced (Restricted Sites zone).'
  desc 'Protected mode protects Internet Explorer from exploited vulnerabilities by reducing the locations Internet Explorer can write to in the registry and the file system.  If you enable this policy setting, Protected Mode will be turned on. Users will not be able to turn off protected mode.  If you disable this policy setting, Protected Mode will be turned off. It will revert to Internet Explorer 6 behavior that allows for Internet Explorer to write to the registry and the file system. Users will not be able to turn on protected mode.  If you do not configure this policy, users will be able to turn on or off protected mode.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Turn on Protected Mode" must be “Enabled” and "Enable" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 2500 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Turn on Protected Mode" to “Enabled” and select "Enable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39391r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15528'
  tag rid: 'SV-40652r1_rule'
  tag stig_id: 'DTBI490'
  tag gtitle: 'DTBI490 - Protected Mode - Restricted'
  tag fix_id: 'F-34509r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
