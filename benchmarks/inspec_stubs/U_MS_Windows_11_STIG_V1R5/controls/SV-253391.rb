control 'SV-253391' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

Value Name: EnumerateAdministrators

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56844r829255_chk'
  tag severity: 'medium'
  tag gid: 'V-253391'
  tag rid: 'SV-253391r829257_rule'
  tag stig_id: 'WN11-CC-000200'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-56794r829256_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
