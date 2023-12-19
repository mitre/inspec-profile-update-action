control 'SV-45288' do
  title 'Protected Mode must be enforced (Internet zone).'
  desc 'Protected mode protects Internet Explorer from exploited vulnerabilities by reducing the locations Internet Explorer can write to in the registry and the file system. If you enable this policy setting, Protected Mode will be turned on. Users will not be able to turn off protected mode. If you disable this policy setting, Protected Mode will be turned off. It will revert to Internet Explorer 6 behavior that allows for Internet Explorer to write to the registry and the file system. Users will not be able to turn on protected mode. If you do not configure this policy, users will be able to turn on or off protected mode.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Turn on Protected Mode" must be "Enabled", and "Enable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 2500 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Turn on Protected Mode" to "Enabled", and select "Enable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15527'
  tag rid: 'SV-45288r2_rule'
  tag stig_id: 'DTBI485'
  tag gtitle: 'DTBI485 - Protected Mode - Internet'
  tag fix_id: 'F-38684r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
