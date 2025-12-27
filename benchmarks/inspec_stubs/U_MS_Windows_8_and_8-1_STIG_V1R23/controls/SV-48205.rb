control 'SV-48205' do
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.'
  desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow drive redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44884r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14249'
  tag rid: 'SV-48205r2_rule'
  tag stig_id: 'WN08-CC-000098'
  tag gtitle: 'TS/RDS - Drive Redirection'
  tag fix_id: 'F-41341r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
