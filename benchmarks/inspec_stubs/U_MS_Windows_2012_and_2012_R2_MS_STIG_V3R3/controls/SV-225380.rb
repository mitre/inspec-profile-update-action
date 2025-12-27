control 'SV-225380' do
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).'
  desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow drive redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27079r471482_chk'
  tag severity: 'medium'
  tag gid: 'V-225380'
  tag rid: 'SV-225380r569185_rule'
  tag stig_id: 'WN12-CC-000098'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27067r471483_fix'
  tag 'documentable'
  tag legacy: ['SV-52959', 'V-14249']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
