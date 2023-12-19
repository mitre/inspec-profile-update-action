control 'SV-29572' do
  title 'Defender – SpyNet Reporting'
  desc 'This check verifies that SpyNet membership is disabled.'
  desc 'check', 'If the following registry value exists and is set to “1” (Basic) or “2” (Advanced), this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows Defender\\Spynet\\

Value Name:  SpyNetReporting

Type:  REG_DWORD
Value:  1 or 2 = a Finding'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender “Configure Microsoft Spynet Reporting” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15713'
  tag rid: 'SV-29572r1_rule'
  tag gtitle: 'Defender – SpyNet Reporting'
  tag fix_id: 'F-15605r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
