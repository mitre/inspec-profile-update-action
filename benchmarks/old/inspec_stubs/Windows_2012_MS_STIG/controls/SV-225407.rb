control 'SV-225407' do
  title 'Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
  desc 'Preventing the redirection of Plug and Play devices in Remote Desktop sessions helps reduce possible exposure of sensitive data.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fDisablePNPRedir

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow supported Plug and Play device redirection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27106r471563_chk'
  tag severity: 'medium'
  tag gid: 'V-225407'
  tag rid: 'SV-225407r852232_rule'
  tag stig_id: 'WN12-CC-000135'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-27094r471564_fix'
  tag 'documentable'
  tag legacy: ['SV-52229', 'V-15999']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
