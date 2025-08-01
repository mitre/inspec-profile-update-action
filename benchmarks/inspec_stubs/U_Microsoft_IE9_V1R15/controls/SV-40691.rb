control 'SV-40691' do
  title 'AutoComplete feature for forms must be disallowed.'
  desc 'This AutoComplete feature suggests possible matches when users are filling in forms. If you enable this setting, the user is not suggested matches when filling forms. The user cannot change it. If you disable this setting, the user is suggested possible matches when filling forms. The user cannot change it. If you do not configure this setting, the user has the freedom to turn on the auto-complete feature for forms. To display this option, the users open the Internet Options dialog box, click the Contents Tab and click the Settings button.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable AutoComplete for forms" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value Use FormSuggest is REG_SZ = no, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable AutoComplete for forms" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39421r4_chk'
  tag severity: 'medium'
  tag gid: 'V-15574'
  tag rid: 'SV-40691r1_rule'
  tag stig_id: 'DTBI690'
  tag gtitle: 'DTBI690 - AutoComplete for forms'
  tag fix_id: 'F-34549r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
