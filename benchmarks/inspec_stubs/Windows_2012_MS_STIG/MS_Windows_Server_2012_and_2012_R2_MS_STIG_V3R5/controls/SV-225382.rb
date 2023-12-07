control 'SV-225382' do
  title 'Remote Desktop Services must be configured with the client connection encryption set to the required level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Set client connection encryption level" to "Enabled" and "High Level".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27081r471488_chk'
  tag severity: 'medium'
  tag gid: 'V-225382'
  tag rid: 'SV-225382r852221_rule'
  tag stig_id: 'WN12-CC-000100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-27069r471489_fix'
  tag 'documentable'
  tag legacy: ['V-3454', 'SV-52899']
  tag cci: ['CCI-000068', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'MA-4 (6)']
end
