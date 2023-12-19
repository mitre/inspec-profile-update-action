control 'SV-225404' do
  title 'Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop Services Role).'
  desc "Preventing the redirection of Remote Desktop session data to a client computer's COM ports helps reduce possible exposure of sensitive data."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableCcm

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow COM port redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27103r471554_chk'
  tag severity: 'medium'
  tag gid: 'V-225404'
  tag rid: 'SV-225404r852229_rule'
  tag stig_id: 'WN12-CC-000132'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-27091r471555_fix'
  tag 'documentable'
  tag legacy: ['SV-52224', 'V-15997']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
