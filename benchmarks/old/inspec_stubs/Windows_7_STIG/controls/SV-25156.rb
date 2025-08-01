control 'SV-25156' do
  title 'Disable Internet File Association Service.'
  desc 'This check verifies that unhandled file associations will not use the Microsoft Web service to find an application.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoInternetOpenWith

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Internet File Association service” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15318r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15674'
  tag rid: 'SV-25156r1_rule'
  tag gtitle: 'Internet File Association Service'
  tag fix_id: 'F-15541r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
