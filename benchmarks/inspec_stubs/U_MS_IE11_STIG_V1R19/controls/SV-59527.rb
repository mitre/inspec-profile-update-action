control 'SV-59527' do
  title 'Java permissions must be disallowed (Locked Down Restricted Sites zone).'
  desc 'Java applications could contain malicious code. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of the Custom permission will control permissions settings individually. Use of the Low Safety permission enables applets to perform all operations. Use of the Medium Safety permission enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus adds capabilities like scratch space (a safe and secure storage area on the client computer) and a user-controlled file I/O. Use of the High Safety permission enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> 'Java permissions' must be 'Enabled', and 'Disable Java' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following keys: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4 Criteria: If the value "1C00" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> 'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49821r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46663'
  tag rid: 'SV-59527r1_rule'
  tag stig_id: 'DTBI450-IE11'
  tag gtitle: 'DTBI450-IE11-Java permission - Locked Down Restricted Sites'
  tag fix_id: 'F-50431r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCMC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
