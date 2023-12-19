control 'SV-32394' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to enter a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-74329r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14243'
  tag rid: 'SV-32394r2_rule'
  tag gtitle: 'Enumerate Administrator Accounts on Elevation'
  tag fix_id: 'F-80999r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
