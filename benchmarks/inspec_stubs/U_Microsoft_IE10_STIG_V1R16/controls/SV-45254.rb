control 'SV-45254' do
  title 'Java permissions must be disallowed (Locked Down Intranet zone).'
  desc 'Java applications could contain malicious code. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of Custom will control permissions settings individually. Use of Low Safety enables applets to perform all operations. Use of Medium Safety enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus capabilities like scratch space (a safe and secure storage area on the client computer) and user-controlled file I/O. Use of High Safety enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Intranet Zone -> "Java permissions" must be "Enabled", and "Disable Java" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following keys: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\1 

Criteria: If the value 1C00 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Intranet Zone -> "Java permissions" to "Enabled", and select "Disable Java" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15517'
  tag rid: 'SV-45254r2_rule'
  tag stig_id: 'DTBI435'
  tag gtitle: 'DTBI435 - Java permission - Locked Down Intranet'
  tag fix_id: 'F-38650r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
