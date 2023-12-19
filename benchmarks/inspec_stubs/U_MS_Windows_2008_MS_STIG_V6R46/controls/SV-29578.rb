control 'SV-29578' do
  title 'Windows Mail – Communities'
  desc 'This check verifies that Windows Mail will not check newsgroups for Communities support.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows Mail\\

Value Name:	DisableCommunities

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Mail “Turn off the communities features” to “Enabled”'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15408r1_chk'
  tag severity: 'low'
  tag gid: 'V-15720'
  tag rid: 'SV-29578r1_rule'
  tag gtitle: 'Windows Mail – Communities'
  tag fix_id: 'F-15612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
