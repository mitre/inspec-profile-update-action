control 'SV-223061' do
  title 'Java permissions must be disallowed (Restricted Sites zone).'
  desc 'Java applications could contain malicious code; sites located in this security zone are more likely to be hosted by malicious individuals. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of the Custom permission will control permissions settings individually. Use of the Low Safety permission enables applets to perform all operations. Use of the Medium Safety permission enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus adds capabilities like scratch space (a safe and secure storage area on the client computer) and a user-controlled file I/O. Use of the High Safety permission enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Java permissions' must be 'Enabled', and 'Disable Java' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1C00" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24734r428733_chk'
  tag severity: 'medium'
  tag gid: 'V-223061'
  tag rid: 'SV-223061r428735_rule'
  tag stig_id: 'DTBI121-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24722r428734_fix'
  tag 'documentable'
  tag legacy: ['SV-59451', 'V-46587']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
