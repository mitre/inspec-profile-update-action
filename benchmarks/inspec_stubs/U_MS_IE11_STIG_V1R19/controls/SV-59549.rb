control 'SV-59549' do
  title 'Protected Mode must be enforced (Restricted Sites zone).'
  desc 'Protected Mode protects Internet Explorer from exploited vulnerabilities by reducing the locations Internet Explorer can write to in the registry and the file system. If you enable this policy setting, Protected Mode will be turned on. Users will not be able to turn off Protected Mode. If you disable this policy setting, Protected Mode will be turned off. It will revert to Internet Explorer 6 behavior that allows for Internet Explorer to write to the registry and the file system. Users will not be able to turn on Protected Mode. If you do not configure this policy, users will be able to turn on or off Protected Mode.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Turn on Protected Mode' must be 'Enabled', and 'Enable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2500" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Turn on Protected Mode' to 'Enabled' and select 'Enable', from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49837r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46685'
  tag rid: 'SV-59549r1_rule'
  tag stig_id: 'DTBI490-IE11'
  tag gtitle: 'DTBI490-IE11-Protected Mode - Restricted Sites'
  tag fix_id: 'F-50449r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
