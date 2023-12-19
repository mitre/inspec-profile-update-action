control 'SV-59533' do
  title 'XAML files must be disallowed (Restricted Sites zone).'
  desc 'These are eXtensible Application Markup Language (XAML) files. XAML is an XML-based declarative markup language commonly used for creating rich user interfaces and graphics that leverage the Windows Presentation Foundation. If you enable this policy setting and the drop-down box is set to Enable, XAML files will be automatically loaded inside Internet Explorer. Users will not be able to change this behavior. If the drop-down box is set to Prompt, users will receive a prompt for loading XAML files. If you disable this policy setting, XAML files will not be loaded inside Internet Explorer. Users will not be able to change this behavior. If you do not configure this policy setting, users will have the freedom to decide whether to load XAML files inside Internet Explorer.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow loading of XAML files' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2402" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49825r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46669'
  tag rid: 'SV-59533r1_rule'
  tag stig_id: 'DTBI460-IE11'
  tag gtitle: 'DTBI460-IE11-Loading of XAML files - Restricted Sites'
  tag fix_id: 'F-50435r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
