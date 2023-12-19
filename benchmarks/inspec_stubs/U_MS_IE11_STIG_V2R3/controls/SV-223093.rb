control 'SV-223093' do
  title 'Protected Mode must be enforced (Internet zone).'
  desc 'Protected Mode protects Internet Explorer from exploited vulnerabilities by reducing the locations Internet Explorer can write to in the registry and the file system. If you enable this policy setting, Protected Mode will be turned on. Users will not be able to turn off Protected Mode. If you disable this policy setting, Protected Mode will be turned off. It will revert to Internet Explorer 6 behavior that allows for Internet Explorer to write to the registry and the file system. Users will not be able to turn on Protected Mode. If you do not configure this policy, users will be able to turn on or off Protected Mode.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Turn on Protected Mode' must be 'Enabled', and 'Enable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2500" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24766r428829_chk'
  tag severity: 'medium'
  tag gid: 'V-223093'
  tag rid: 'SV-223093r428831_rule'
  tag stig_id: 'DTBI485-IE11'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-24754r428830_fix'
  tag 'documentable'
  tag legacy: ['SV-59545', 'V-46681']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
