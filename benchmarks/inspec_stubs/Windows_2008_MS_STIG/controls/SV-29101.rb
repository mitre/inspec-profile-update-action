control 'SV-29101' do
  title 'Terminal Services is configured to use a common temporary folder for all sessions (Terminal Server Role).'
  desc 'This setting, which is located under the Temporary Folders section of the Terminal Services configuration option, controls the use of per session temporary folders or of a communal temporary folder.  If this setting is enabled, only one temporary folder is used for all terminal services sessions.  If a communal temporary folder is used, it might be possible for users to access other users temporary folders.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  PerSessionTempDir

Type:  REG_DWORD
Value:  1'
  desc 'fix', '2008/Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Temporary Folders “Do Not Use Temp Folders per Session” will be set to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-1899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3455'
  tag rid: 'SV-29101r1_rule'
  tag gtitle: 'TS/RDS - Do Not Use Temp Folders'
  tag fix_id: 'F-16024r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
