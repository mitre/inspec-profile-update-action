control 'SV-32497' do
  title 'Local drives will be prevented from sharing with Remote Desktop Session Hosts (Remote Desktop Services Role).'
  desc 'This check verifies that the system is configured to prevent users from sharing the local drives on their client computers to Remote Desktop Session Hosts that they access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDisableCdm

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection “Do not allow drive redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-11595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14249'
  tag rid: 'SV-32497r2_rule'
  tag gtitle: 'TS/RDS - Drive Redirection'
  tag fix_id: 'F-28884r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
