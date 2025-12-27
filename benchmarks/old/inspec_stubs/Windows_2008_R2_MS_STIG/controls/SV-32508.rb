control 'SV-32508' do
  title 'The system will be configured to allow only the default client printer to be redirected in the Remote Desktop session. (Remote Desktop Services Role)'
  desc 'This check verifies that the system is configured to allow only the default client printer to be redirected in the Remote Desktop session.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  RedirectOnlyDefaultClientPrinter

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Printer Redirection “Redirect only the default client printer” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32909r1_chk'
  tag severity: 'low'
  tag gid: 'V-16001'
  tag rid: 'SV-32508r2_rule'
  tag gtitle: 'TS/RDS – Printer Redirection'
  tag fix_id: 'F-28928r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
