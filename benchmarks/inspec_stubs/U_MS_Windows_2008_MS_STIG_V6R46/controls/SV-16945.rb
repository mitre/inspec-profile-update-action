control 'SV-16945' do
  title 'Terminal Services – Default Only Client Printer Redirection (Terminal Server Role).'
  desc 'This check verifies that the system is configured to allow only the default client printer to be redirected in the Terminal Services session.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  RedirectOnlyDefaultClientPrinter

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Printer Redirection “Redirect only the default client printer” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32909r1_chk'
  tag severity: 'low'
  tag gid: 'V-16001'
  tag rid: 'SV-16945r1_rule'
  tag gtitle: 'TS/RDS – Printer Redirection'
  tag fix_id: 'F-16016r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
