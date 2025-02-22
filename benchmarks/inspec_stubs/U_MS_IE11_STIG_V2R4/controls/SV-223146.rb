control 'SV-223146' do
  title 'Scriptlets must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to manage whether scriptlets can be allowed. Scriptlets hosted on sites located in this zone are more likely to contain malicious code. If you enable this policy setting, users will be able to run scriptlets. If you disable this policy setting, users will not be able to run scriptlets. If you do not configure this policy setting, a scriptlet can be enabled or disabled by the user.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 'Allow Scriptlets' must be 'Enabled', and 'Disable' selected from the drop-down box.  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1209" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24819r428988_chk'
  tag severity: 'medium'
  tag gid: 'V-223146'
  tag rid: 'SV-223146r879587_rule'
  tag stig_id: 'DTBI940-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24807r428989_fix'
  tag 'documentable'
  tag legacy: ['SV-59793', 'V-46927']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
