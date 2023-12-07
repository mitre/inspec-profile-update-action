control 'SV-224948' do
  title 'Remote Desktop Services must be configured with the client connection encryption set to High Level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 0x00000003 (3)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Set client connection encryption level" to "Enabled" with "High Level" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26639r465746_chk'
  tag severity: 'medium'
  tag gid: 'V-224948'
  tag rid: 'SV-224948r877394_rule'
  tag stig_id: 'WN16-CC-000410'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-26627r465747_fix'
  tag 'documentable'
  tag legacy: ['SV-88239', 'V-73575']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
