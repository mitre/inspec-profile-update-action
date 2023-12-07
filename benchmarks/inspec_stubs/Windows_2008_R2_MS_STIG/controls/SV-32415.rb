control 'SV-32415' do
  title 'The classic logon screen must be required for user logons.'
  desc 'The classic logon screen requires users to enter a logon name and password to access a system.  The simple logon screen or Welcome screen displays usernames for selection, providing part of the necessary logon information.'
  desc 'check', 'If the system is a member of a domain, this is NA.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  LogonType

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'If the system is a member of a domain, this is NA.
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Always use classic logon" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-59053r2_chk'
  tag severity: 'low'
  tag gid: 'V-15680'
  tag rid: 'SV-32415r2_rule'
  tag stig_id: '5.223-MS'
  tag gtitle: 'Classic Logon'
  tag fix_id: 'F-63541r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
