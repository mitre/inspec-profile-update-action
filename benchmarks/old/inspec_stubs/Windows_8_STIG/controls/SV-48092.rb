control 'SV-48092' do
  title 'Remote Desktop Services must delete temporary folders when a session is terminated.'
  desc 'Remote desktop session temporary folders must always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.  This setting controls the deletion of the temporary folders when the session is terminated.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DeleteTempDirsOnExit

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not delete temp folder upon exit" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3456'
  tag rid: 'SV-48092r1_rule'
  tag stig_id: 'WN08-CC-000103'
  tag gtitle: 'TS/RDS - Delete Temp Folders'
  tag fix_id: 'F-41230r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
