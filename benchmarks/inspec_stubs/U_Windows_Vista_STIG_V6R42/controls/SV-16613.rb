control 'SV-16613' do
  title 'Terminal Services is not configured to set a time limit for disconnected sessions.'
  desc 'This setting controls how long a session will remain open if it is unexpectedly terminated.  Such sessions should be terminated as soon as possible.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  MaxDisconnectionTime

Type:  REG_DWORD
Value:  0x0000ea60 (60000)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Session Time Limits “Set Time Limit for Disconnected Sessions” to “Enabled”, and the “End a disconnected session” set to “1 minute".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-32896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3457'
  tag rid: 'SV-16613r1_rule'
  tag gtitle: 'TS/RDS - Time Limit for Disc. Session'
  tag fix_id: 'F-34275r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
