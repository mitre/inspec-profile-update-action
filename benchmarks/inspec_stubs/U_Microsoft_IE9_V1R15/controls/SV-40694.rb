control 'SV-40694' do
  title 'AutoComplete feature for user names and passwords on forms must be disallowed.'
  desc %q(It is possible this feature will cache sensitive data and store it in the user's profile where it might not be protected as rigorously as required by organizational policy. This policy setting controls automatic completion of fields in forms on web pages. If you enable this setting, the user cannot change "User name and passwords on forms" or "prompt me to save passwords". The Auto Complete feature for user names and passwords on forms will be turned on. If you disable this setting, the user cannot change "User name and passwords on forms" or "prompt me to save passwords". The Auto Complete feature for user names and passwords on forms is turned off. The user also cannot opt to be prompted to save passwords. If you do not configure this setting, the user has the freedom of turning on Auto Complete for user name and passwords on forms, and the option of prompting to save passwords.)
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn on the auto-complete feature for user names and passwords on forms" must be “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Main 

Criteria: If the value FormSuggest Passwords is REG_SZ = no, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn on the auto-complete feature for user names and passwords on forms" to “Disabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39424r4_chk'
  tag severity: 'medium'
  tag gid: 'V-15581'
  tag rid: 'SV-40694r1_rule'
  tag stig_id: 'DTBI725'
  tag gtitle: 'DTBI725 - U/N and Pwd auto-complete feature'
  tag fix_id: 'F-34552r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
