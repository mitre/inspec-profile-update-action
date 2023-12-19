control 'SV-40642' do
  title 'Java permissions must be disallowed (Locked Down Restricted Sites zone).'
  desc 'Java applications could contain malicious code; sites located in this security zone are more likely to be hosted by malicious people. This policy setting allows you to manage permissions for Java Applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of Custom will control permissions settings individually. Use of Low Safety enables applets to perform all operations. Use of Medium Safety enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus capabilities like scratch space (a safe and secure storage area on the client computer) and user-controlled file I/O. Use of High Safety enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> "Java permissions" must be “Enabled” and "Disable Java" selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following keys: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\4 

Criteria: If the value 1C00 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone -> "Java permissions" to “Enabled” and select "Disable Java" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39380r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15520'
  tag rid: 'SV-40642r2_rule'
  tag stig_id: 'DTBI450'
  tag gtitle: 'DTBI450 - Java permission - Locked Down Restricted'
  tag fix_id: 'F-34497r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCMC-1'
end
