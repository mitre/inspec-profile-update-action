control 'SV-225316' do
  title 'Windows Peer-to-Peer networking services must be turned off.'
  desc 'Peer-to-Peer applications can allow unauthorized access to a system and exposure of sensitive data.  This setting will turn off the Microsoft Peer-to-Peer Networking Service.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Peernet\\

Value Name: Disabled

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services -> "Turn off Microsoft Peer-to-Peer Networking Services" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27015r471290_chk'
  tag severity: 'medium'
  tag gid: 'V-225316'
  tag rid: 'SV-225316r569185_rule'
  tag stig_id: 'WN12-CC-000003'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27003r471291_fix'
  tag 'documentable'
  tag legacy: ['SV-53012', 'V-15666']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
