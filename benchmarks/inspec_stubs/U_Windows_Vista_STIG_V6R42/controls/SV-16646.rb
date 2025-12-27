control 'SV-16646' do
  title 'Remote Assistance – Session Logging'
  desc 'This check verifies that Remote Assistance log files will be generated.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  LoggingEnabled

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance “Turn on session logging” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15395r1_chk'
  tag severity: 'low'
  tag gid: 'V-15707'
  tag rid: 'SV-16646r1_rule'
  tag gtitle: 'Remote Assistance – Session Logging'
  tag fix_id: 'F-15599r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
