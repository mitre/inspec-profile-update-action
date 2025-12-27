control 'SV-226227' do
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
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27929r476004_chk'
  tag severity: 'medium'
  tag gid: 'V-226227'
  tag rid: 'SV-226227r852122_rule'
  tag stig_id: 'WN12-CC-000135'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-27917r476005_fix'
  tag 'documentable'
  tag legacy: ['SV-52229', 'V-15999']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
