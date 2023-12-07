control 'SV-225369' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to enter in a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27068r471449_chk'
  tag severity: 'medium'
  tag gid: 'V-225369'
  tag rid: 'SV-225369r569185_rule'
  tag stig_id: 'WN12-CC-000077'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27056r471450_fix'
  tag 'documentable'
  tag legacy: ['V-14243', 'SV-52955']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
