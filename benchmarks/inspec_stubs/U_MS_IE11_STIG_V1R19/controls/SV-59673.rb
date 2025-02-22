control 'SV-59673' do
  title 'AutoComplete feature for forms must be disallowed.'
  desc %q(This AutoComplete feature suggests possible matches when users are filling in forms. It is possible that this feature will cache sensitive data and store it in the user's profile, where it might not be protected as rigorously as required by organizational policy. If you enable this setting, the user is not presented with suggested matches when filling in forms. If you disable this setting, the user is presented with suggested possible matches when filling forms. If you do not configure this setting, the user has the freedom to turn on the auto-complete feature for forms. To display this option, the user opens the Internet Options dialog box, clicks the "Contents" tab, and clicks the "Settings" button.)
  desc 'check', %q(The policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Disable AutoComplete for forms' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKCU\Software\Policies\Microsoft\Internet Explorer\Main Criteria: If the value "Use FormSuggest" is REG_SZ = no, this is not a finding.)
  desc 'fix', "Set the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> 'Disable AutoComplete for forms' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49899r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46807'
  tag rid: 'SV-59673r1_rule'
  tag stig_id: 'DTBI690-IE11'
  tag gtitle: 'DTBI690-IE11-AutoComplete for forms'
  tag fix_id: 'F-50557r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
