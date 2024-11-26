control 'SV-14878' do
  title 'A password will be required on resume from hibernate/suspend.'
  desc 'This check verifies that the user is prompted for a password on resume from hibernate/suspend.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\System\\Power\\

Value Name:  PromptPasswordOnResume

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> System ->Power Management -> “Prompt for password on resume from hibernate/suspend” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-11757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14267'
  tag rid: 'SV-14878r1_rule'
  tag gtitle: 'Power Mgmt - Require Password on Resume'
  tag fix_id: 'F-13605r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
