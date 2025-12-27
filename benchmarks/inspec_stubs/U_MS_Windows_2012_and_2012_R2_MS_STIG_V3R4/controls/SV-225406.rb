control 'SV-225406' do
  title 'The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session.  (Remote Desktop Services Role).'
  desc 'Enabling the redirection of smart card devices allows their use within Remote Desktop sessions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fEnableSmartCard

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow smart card device redirection" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27105r471560_chk'
  tag severity: 'medium'
  tag gid: 'V-225406'
  tag rid: 'SV-225406r569185_rule'
  tag stig_id: 'WN12-CC-000134'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-27093r471561_fix'
  tag 'documentable'
  tag legacy: ['SV-52230', 'V-16000']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
