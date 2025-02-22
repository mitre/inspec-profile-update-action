control 'SV-88139' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73487'
  tag rid: 'SV-88139r1_rule'
  tag stig_id: 'WN16-CC-000280'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-79929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
