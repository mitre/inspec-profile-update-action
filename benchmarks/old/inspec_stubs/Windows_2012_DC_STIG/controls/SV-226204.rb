control 'SV-226204' do
  title 'Remote Desktop Services must be configured to use session-specific temporary folders.'
  desc "If a communal temporary folder is used for remote desktop sessions, it might be possible for users to access other users' temporary folders.  If this setting is enabled, only one temporary folder is used for all remote desktop sessions.  Per session temporary folders must be established."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: PerSessionTempDir

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not use temporary folders per session" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27906r475935_chk'
  tag severity: 'medium'
  tag gid: 'V-226204'
  tag rid: 'SV-226204r794503_rule'
  tag stig_id: 'WN12-CC-000104'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27894r475936_fix'
  tag 'documentable'
  tag legacy: ['SV-52900', 'V-3455']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
