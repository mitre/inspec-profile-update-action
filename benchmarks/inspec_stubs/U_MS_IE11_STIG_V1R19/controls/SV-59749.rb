control 'SV-59749' do
  title 'Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone).'
  desc 'This policy setting controls whether a page may control embedded WebBrowser Control via script. Scripted code hosted on sites located in this zone is more likely to contain malicious code. If you enable this policy setting, script access to the WebBrowser Control is allowed. If you disable this policy setting, script access to the WebBrowser Control is not allowed. If you do not configure this policy setting, script access to the WebBrowser Control can be enabled or disabled by the user. By default, script access to the WebBrowser Control is only allowed in the Local Machine and Intranet Zones.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow scripting of Internet Explorer WebBrowser controls' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1206" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49943r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46883'
  tag rid: 'SV-59749r1_rule'
  tag stig_id: 'DTBI850-IE11'
  tag gtitle: 'DTBI850-IE11-Scripting of WebBrowser Control - Restricted Sites'
  tag fix_id: 'F-50621r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
