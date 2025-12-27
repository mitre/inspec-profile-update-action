control 'SV-16977' do
  title 'Help Experience Improvement Program is disabled.'
  desc 'This check verifies that the Windows Help Experience Improvement Program is disabled to prevent information from being passed to the vendor.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0

Value Name:  NoImplicitFeedback

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> “Turn off Help Experience Improvement Program” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-16744r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16021'
  tag rid: 'SV-16977r1_rule'
  tag gtitle: 'Help Experience Improvement Program'
  tag fix_id: 'F-16062r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
