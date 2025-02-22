control 'SV-25265' do
  title 'Remote Desktop Services is not configured to delete temporary folders.'
  desc 'This setting controls the deletion of the temporary folders when the session is terminated.  Temporary folders should always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  DeleteTempDirsOnExit

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders “Do not delete temp folder upon exit” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-1906r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3456'
  tag rid: 'SV-25265r1_rule'
  tag gtitle: 'TS/RDS - Delete Temp Folders'
  tag fix_id: 'F-22933r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
