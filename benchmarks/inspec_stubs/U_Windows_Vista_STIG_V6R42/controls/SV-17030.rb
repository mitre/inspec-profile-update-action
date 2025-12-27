control 'SV-17030' do
  title 'Disable Help Ratings feed back.'
  desc 'This check verifies that the users cannot provide ratings feedback to Microsoft for Help content'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0

Value Name:  NoExplicitFeedback

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> “Turn off Help Ratings” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-17017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16048'
  tag rid: 'SV-17030r1_rule'
  tag gtitle: 'Help Ratings'
  tag fix_id: 'F-16132r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
