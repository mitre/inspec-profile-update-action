control 'SV-223090' do
  title 'Java permissions must be disallowed (Locked Down Restricted Sites zone).'
  desc 'Java applications could contain malicious code. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of the Custom permission will control permissions settings individually. Use of the Low Safety permission enables applets to perform all operations. Use of the Medium Safety permission enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus adds capabilities like scratch space (a safe and secure storage area on the client computer) and a user-controlled file I/O. Use of the High Safety permission enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> 'Java permissions' must be 'Enabled', and 'Disable Java' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following keys: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4 Criteria: If the value "1C00" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> 'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24763r428820_chk'
  tag severity: 'medium'
  tag gid: 'V-223090'
  tag rid: 'SV-223090r879587_rule'
  tag stig_id: 'DTBI450-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24751r428821_fix'
  tag 'documentable'
  tag legacy: ['SV-59527', 'V-46663']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
