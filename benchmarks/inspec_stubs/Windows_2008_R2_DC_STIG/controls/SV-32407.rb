control 'SV-32407' do
  title 'Windows Peer-to-Peer networking services will be turned off.'
  desc 'This check verifies Microsoft Peer-to-Peer Networking Service is turned off.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Peernet\\

Value Name:  Disabled

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services “Turn Off Microsoft Peer-to-Peer Networking Services” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15310r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15666'
  tag rid: 'SV-32407r1_rule'
  tag gtitle: 'Windows Peer to Peer Networking'
  tag fix_id: 'F-15530r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
