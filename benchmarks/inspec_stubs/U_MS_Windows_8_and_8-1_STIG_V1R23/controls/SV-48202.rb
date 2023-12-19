control 'SV-48202' do
  title 'The system must require username and password to elevate a running application.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to type in a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14243'
  tag rid: 'SV-48202r2_rule'
  tag stig_id: 'WN08-CC-000077'
  tag gtitle: 'Enumerate Administrator Accounts on Elevation'
  tag fix_id: 'F-41338r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
