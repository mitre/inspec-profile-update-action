control 'SV-29198' do
  title 'Terminal Services / Remote Desktop Services - Local drives prevented from sharing with Terminal Servers (Terminal Server Role).'
  desc 'This check verifies that the system is configured to prevent users from sharing the local drives on their client computers to Terminal Servers that they access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDisableCdm

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Device and Resource Redirection “Do not allow drive redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-11595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14249'
  tag rid: 'SV-29198r1_rule'
  tag gtitle: 'TS/RDS - Drive Redirection'
  tag fix_id: 'F-13574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
