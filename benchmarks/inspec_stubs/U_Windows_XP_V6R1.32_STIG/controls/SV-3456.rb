control 'SV-3456' do
  title 'Terminal Services is not configured to delete temporary folders.'
  desc 'This setting, which is located under the Temporary Folders section of the Terminal Services configuration option, controls the deletion of the temporary folders when the session is terminated.  Temporary folders should always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  DeleteTempDirsOnExit

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Temporary Folders “Do Not Delete Temp Folder upon Exit” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-1906r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3456'
  tag rid: 'SV-3456r1_rule'
  tag gtitle: 'TS/RDS - Delete Temp Folders'
  tag fix_id: 'F-5928r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECRC-1'
end
