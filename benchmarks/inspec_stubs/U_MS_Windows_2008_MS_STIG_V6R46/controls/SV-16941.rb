control 'SV-16941' do
  title 'Terminal Services – Prevent COM Port Redirection (Terminal Server Role).'
  desc 'This check verifies that the system is configured to prevent users from mapping local COM ports and redirecting data from the Terminal Server to local COM ports.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDisableCcm

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Device and Resource Redirection “Do not allow COM port redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15997'
  tag rid: 'SV-16941r1_rule'
  tag gtitle: 'TS/RDS – COM Port Redirection'
  tag fix_id: 'F-16012r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
