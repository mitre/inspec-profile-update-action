control 'SV-45420' do
  title 'The Java permissions must be disallowed (Internet zone).'
  desc 'Java applications could contain malicious code; sites located in this security zone are more likely to be hosted by malicious individuals. This policy setting allows you to manage permissions for Java applets. If you enable this policy setting, options can be chosen from the drop-down box. Use of Custom will control permissions settings individually. Use of Low Safety enables applets to perform all operations. Use of Medium Safety enables applets to run in their sandbox (an area in memory outside of which the program cannot make calls), plus capabilities like scratch space (a safe and secure storage area on the client computer) and user-controlled file I/O. Use of High Safety enables applets to run in their sandbox. If you disable this policy setting, Java applets cannot run. If you do not configure this policy setting, the permission is set to High Safety.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Java permissions" must be "Enabled", and "Disable Java" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1C00 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Java permissions" to "Enabled", and select "Disable Java" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42770r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6249'
  tag rid: 'SV-45420r2_rule'
  tag stig_id: 'DTBI031'
  tag gtitle: 'DTBI031 - Java Permission - Internet'
  tag fix_id: 'F-38817r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
