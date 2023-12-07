control 'SV-48220' do
  title 'Windows Peer-to-Peer networking services must be turned off.'
  desc 'Peer-to-Peer applications can allow unauthorized access to a system and exposure of sensitive data.  This setting will turn off the Microsoft Peer-to-Peer Networking Service.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Peernet\\

Value Name: Disabled

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services -> "Turn Off Microsoft Peer-to-Peer Networking Services" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15666'
  tag rid: 'SV-48220r1_rule'
  tag stig_id: 'WN08-CC-000003'
  tag gtitle: 'Windows Peer to Peer Networking'
  tag fix_id: 'F-41356r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
