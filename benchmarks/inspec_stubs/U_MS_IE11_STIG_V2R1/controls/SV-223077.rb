control 'SV-223077' do
  title 'The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on.'
  desc "This policy setting determines whether Internet Explorer 11 uses 64-bit processes (for greater security) or 32-bit processes (for greater compatibility) when running in Enhanced Protected Mode on 64-bit versions of Windows.Important: Some ActiveX controls and toolbars may not be available when 64-bit processes are used. If you enable this policy setting, Internet Explorer 11 will use 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you disable this policy setting, Internet Explorer 11 will use 32-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you don't configure this policy setting, users can turn this feature on or off using Internet Explorer settings. This feature is turned off by default."
  desc 'check', %q(Note: If McAfee ENS Web Control is being used, this is Not Applicable.

The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Advanced Page 'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "Isolation64Bit" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Advanced Page 'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24750r428781_chk'
  tag severity: 'medium'
  tag gid: 'V-223077'
  tag rid: 'SV-223077r428783_rule'
  tag stig_id: 'DTBI356-IE11'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-24738r428782_fix'
  tag 'documentable'
  tag legacy: ['SV-59861', 'V-46995']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
