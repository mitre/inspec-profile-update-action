control 'SV-48090' do
  title 'Remote Desktop Services must be configured to use session-specific temporary folders.'
  desc "If a communal temporary folder is used for remote desktop sessions, it might be possible for users to access other users' temporary folders.  If this setting is enabled, only one temporary folder is used for all remote desktop sessions.  Per session temporary folders must be established."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: PerSessionTempDir

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not use temporary folders per session" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3455'
  tag rid: 'SV-48090r1_rule'
  tag stig_id: 'WN08-CC-000104'
  tag gtitle: 'TS/RDS - Do Not Use Temp Folders'
  tag fix_id: 'F-41228r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
