control 'SV-254369' do
  title 'Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 0x00000003 (3)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> Set client connection encryption level to "Enabled" with "High Level" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57854r848921_chk'
  tag severity: 'medium'
  tag gid: 'V-254369'
  tag rid: 'SV-254369r848923_rule'
  tag stig_id: 'WN22-CC-000380'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-57805r848922_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000250-GPOS-00093']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
