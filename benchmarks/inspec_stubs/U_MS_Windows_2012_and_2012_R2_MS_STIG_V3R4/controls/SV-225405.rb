control 'SV-225405' do
  title 'Users must be prevented from mapping local LPT ports and redirecting data from the Remote Desktop Session Host to local LPT ports.  (Remote Desktop Services Role).'
  desc "Preventing the redirection of Remote Desktop session data to a client computer's LPT ports helps reduce possible exposure of sensitive data."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisableLPT

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow LPT port redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27104r471557_chk'
  tag severity: 'medium'
  tag gid: 'V-225405'
  tag rid: 'SV-225405r569185_rule'
  tag stig_id: 'WN12-CC-000133'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-27092r471558_fix'
  tag 'documentable'
  tag legacy: ['SV-52226', 'V-15998']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
