control 'SV-48089' do
  title 'Remote Desktop Services must be configured with the client connection encryption set to the required level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Set client connection encryption level" to "Enabled" and "High Level".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44828r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3454'
  tag rid: 'SV-48089r1_rule'
  tag stig_id: 'WN08-CC-000100'
  tag gtitle: 'TS/RDS - Set Encryption Level'
  tag fix_id: 'F-41226r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'MA-4 (6)']
end
