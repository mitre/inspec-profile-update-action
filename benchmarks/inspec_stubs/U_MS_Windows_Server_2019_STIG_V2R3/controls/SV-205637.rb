control 'SV-205637' do
  title 'Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 0x00000003 (3)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Set client connection encryption level" to "Enabled" with "High Level" selected.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5902r354829_chk'
  tag severity: 'medium'
  tag gid: 'V-205637'
  tag rid: 'SV-205637r569188_rule'
  tag stig_id: 'WN19-CC-000380'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-5902r354830_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000250-GPOS-00093']
  tag 'documentable'
  tag legacy: ['V-92973', 'SV-103061']
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
