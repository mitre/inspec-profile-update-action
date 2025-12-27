control 'SV-226203' do
  title 'Remote Desktop Services must delete temporary folders when a session is terminated.'
  desc 'Remote desktop session temporary folders must always be deleted after a session is over to prevent hard disk clutter and potential leakage of information.  This setting controls the deletion of the temporary folders when the session is terminated.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DeleteTempDirsOnExit

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not delete temp folder upon exit" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27905r475932_chk'
  tag severity: 'medium'
  tag gid: 'V-226203'
  tag rid: 'SV-226203r569184_rule'
  tag stig_id: 'WN12-CC-000103'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27893r475933_fix'
  tag 'documentable'
  tag legacy: ['SV-52901', 'V-3456']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
