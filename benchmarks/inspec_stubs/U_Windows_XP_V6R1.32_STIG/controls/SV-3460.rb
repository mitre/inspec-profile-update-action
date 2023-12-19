control 'SV-3460' do
  title 'Terminal Services is not configured to disconnect clients when time limits are exceeded.'
  desc 'This setting, which is located under the Sessions section of the Terminal Services configuration option, controls whether or not clients are forcefully disconnected if their terminal services time limit is exceeded.  If time limits are established for users, they should be enforced.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:

Registry Hive:	HKEY_LOCAL_MACHINE
Subkey: 	\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\
Value Name:	fResetBroken
Type: 		REG_DWORD
Value:		1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Sessions “Terminate Session When Time Limits are Reached” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-1929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3460'
  tag rid: 'SV-3460r1_rule'
  tag gtitle: 'Terminal Services - Enforce Session Time Limit'
  tag fix_id: 'F-5936r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
