control 'SV-59681' do
  title 'Turn on the auto-complete feature for user names and passwords on forms must be disabled.'
  desc %q(This policy setting controls automatic completion of fields in forms on web pages. It is possible that malware could be developed which would be able to extract the cached user names and passwords from the currently logged on user, which an attacker could then use to compromise that user's online accounts.  If you enable this setting, the user cannot change the 'User name and passwords on forms' or 'prompt me to save passwords'. The Auto Complete feature for" User names and passwords on forms" will be turned on. If you disable this setting, the user cannot change the 'User name and passwords on forms' or 'prompt me to save passwords'. The Auto Complete feature for "User names and passwords on forms" is turned off. The user also cannot opt to be prompted to save passwords. If you do not configure this setting, the user has the freedom of turning on Auto Complete for "User name and passwords on forms", and the option of prompting to save passwords.)
  desc 'check', %q(The policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn on the auto-complete feature for user names and passwords on forms' must be 'Disabled'. 
Procedure: Use the Windows Registry Editor to navigate to the following key: HKCU\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "FormSuggest Passwords" is REG_SZ = 'no', this is not a finding. AND Procedure: Use the Windows Registry Editor to navigate to the following key: HKCU\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "FormSuggest PW Ask" is REG_SZ = 'no', this is not a finding.)
  desc 'fix', "Set the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Turn on the auto-complete feature for user names and passwords on forms' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49905r3_chk'
  tag severity: 'medium'
  tag gid: 'V-46815'
  tag rid: 'SV-59681r1_rule'
  tag stig_id: 'DTBI725-IE11'
  tag gtitle: 'DTBI725-IE11-Auto-complete feature for user names and passwords'
  tag fix_id: 'F-50563r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
