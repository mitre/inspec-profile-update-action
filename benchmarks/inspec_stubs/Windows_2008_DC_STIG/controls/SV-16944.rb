control 'SV-16944' do
  title 'Terminal Services – Smart Card Device Redirection Enabled (Terminal Server Role).'
  desc 'This check verifies that the system is configured to ensure smart card devices can be redirected to the Terminal Services session.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fEnableSmartCard

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Device and Resource Redirection “Do not allow smart card device redirection” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32908r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16000'
  tag rid: 'SV-16944r1_rule'
  tag gtitle: 'TS/RDS – Smart Card Device Redirection'
  tag fix_id: 'F-16015r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
