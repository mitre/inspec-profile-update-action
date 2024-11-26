control 'SV-3459' do
  title 'Terminal Services is not configured to allow only the original client to reconnect.'
  desc 'This setting, which is located under the Sessions section of the Terminal Services configuration option, controls whether a different client may be used to resume a disconnected session.  Only the original client should be able to resume a session to help prevent session hijacking.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:

Registry Hive:	HKEY_LOCAL_MACHINE
Subkey: 	\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\
Value Name:	fReconnectSame
Type: 		REG_DWORD
Value:		1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Sessions “Allow Reconnection from Original Client Only” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-1925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3459'
  tag rid: 'SV-3459r1_rule'
  tag gtitle: 'Terminal Services  - Original Client Reconnection'
  tag fix_id: 'F-5933r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
