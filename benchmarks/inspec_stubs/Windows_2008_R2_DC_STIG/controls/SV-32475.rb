control 'SV-32475' do
  title 'Game explorer information will not be downloaded from Windows Metadata Services.'
  desc 'This check verifies that game information is not downloaded from Windows Metadata Services.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\GameUX\\

Value Name:  DownloadGameInfo

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Game Explorer “Turn off downloading of game information” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15397r1_chk'
  tag severity: 'low'
  tag gid: 'V-15709'
  tag rid: 'SV-32475r1_rule'
  tag gtitle: 'Game Explorer Information Downloads'
  tag fix_id: 'F-15601r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
