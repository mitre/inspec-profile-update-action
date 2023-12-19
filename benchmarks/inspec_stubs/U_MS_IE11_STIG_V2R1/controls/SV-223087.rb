control 'SV-223087' do
  title 'Java permissions must be disallowed (Locked Down Local Machine zone).'
  desc 'Java applications could contain malicious code. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of the Custom permission will control permissions settings individually. Use of the Low Safety permission enables applets to perform all operations. Use of the Medium Safety permission enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus adds capabilities like scratch space (a safe and secure storage area on the client computer) and a user-controlled file I/O. Use of the High Safety permission enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Local Machine Zone -> 'Java permissions' must be 'Enabled', and 'Disable Java' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following keys: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0 Criteria: If the value "1C00" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Local Machine Zone -> 'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24760r428811_chk'
  tag severity: 'medium'
  tag gid: 'V-223087'
  tag rid: 'SV-223087r428813_rule'
  tag stig_id: 'DTBI430-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24748r428812_fix'
  tag 'documentable'
  tag legacy: ['SV-59511', 'V-46647']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
