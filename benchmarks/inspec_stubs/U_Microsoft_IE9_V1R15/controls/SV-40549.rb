control 'SV-40549' do
  title 'Internet Explorer must be configured to use machine settings.'
  desc 'Users who change their Internet Explorer security settings could enable the execution of dangerous types of code from the Internet and web sites listed in the Restricted Sites zone in the browser. This setting enforces consistent security zone settings to all users of the computer. Security zones control browser behavior at various web sites and it is desirable to maintain a consistent policy for all users of a machine. This policy setting affects how security zone changes apply to different users. If you enable this policy setting, changes that one user makes to a security zone will apply to all users of that computer. If this policy setting is disabled or not configured, users of the same computer are allowed to establish their own security zone settings.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer “Security Zones: Use only machine settings” must be “Enabled”.  

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings 

Criteria: If the value Security_HKLM_only is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer “Security Zones: Use only machine settings”  to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39317r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3427'
  tag rid: 'SV-40549r1_rule'
  tag stig_id: 'DTBI320'
  tag gtitle: 'DTBI320 - Security zone machine settings'
  tag fix_id: 'F-34425r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
