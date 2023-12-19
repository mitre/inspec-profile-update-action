control 'SV-25292' do
  title 'Prevent handwriting personalization data sharing with Microsoft.'
  desc 'This setting prevents data from the handwriting recognition personalization tool being shared with Microsoft.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\TabletPC\\

Value Name:  PreventHandwritingDataSharing

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communications Management - > Internet Communication settings -> “Turn off handwriting personalization data sharing” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26854r1_chk'
  tag severity: 'low'
  tag gid: 'V-21966'
  tag rid: 'SV-25292r1_rule'
  tag gtitle: 'Handwriting personalization data sharing'
  tag fix_id: 'F-22953r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
