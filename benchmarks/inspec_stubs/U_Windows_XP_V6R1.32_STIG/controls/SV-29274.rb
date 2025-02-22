control 'SV-29274' do
  title 'The system is configured to allow remote desktop sharing through NetMeeting.'
  desc 'Remote desktop sharing enables several users to interact and control one desktop.  This could allow unauthorized users to control the system.  Remote desktop sharing should be disabled.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:

Registry Hive:	HKEY_LOCAL_MACHINE
Subkey: 	\\Software\\Policies\\Microsoft\\Conferencing\\
Value Name:	NoRDS
Type: 		REG_DWORD
Value: 		1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> NetMeeting “Disable remote Desktop Sharing” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-1738r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3426'
  tag rid: 'SV-29274r1_rule'
  tag gtitle: 'NetMeeting Disable Remote Desktop Sharing'
  tag fix_id: 'F-5908r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
