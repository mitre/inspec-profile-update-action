control 'SV-225408' do
  title 'Only the default client printer must be redirected to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
  desc 'Allowing the redirection of only the default client printer to a Remote Desktop session helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: RedirectOnlyDefaultClientPrinter

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Printer Redirection -> "Redirect only the default client printer" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27107r471566_chk'
  tag severity: 'medium'
  tag gid: 'V-225408'
  tag rid: 'SV-225408r569185_rule'
  tag stig_id: 'WN12-CC-000136'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-27095r471567_fix'
  tag 'documentable'
  tag legacy: ['SV-52163', 'V-40204']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
