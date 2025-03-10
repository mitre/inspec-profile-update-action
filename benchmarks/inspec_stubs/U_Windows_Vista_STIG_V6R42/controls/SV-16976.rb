control 'SV-16976' do
  title 'Windows Customer Experience Improvement Program is disabled.'
  desc 'This check verifies that the Windows Customer Experience Improvement Program is disabled so information is not passed to the vendor.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_Local_Machine
Subkey:  \\Software\\Policies\\Microsoft\\SQMClient\\Windows

Value Name:  CEIPEnable

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> “Turn off Windows Customer Experience Improvement Program” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-16743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16020'
  tag rid: 'SV-16976r1_rule'
  tag gtitle: 'Windows Customer Experience Improvement Program'
  tag fix_id: 'F-16061r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
