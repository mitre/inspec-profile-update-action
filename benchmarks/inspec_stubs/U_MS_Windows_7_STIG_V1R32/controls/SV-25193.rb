control 'SV-25193' do
  title 'IE security prompt is enabled for web-based installations.'
  desc 'This check verifies that users are notified if a web-based program attempts to install software.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name:  SafeForScripting

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Disable IE security prompt for Windows Installer scripts” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15328r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15684'
  tag rid: 'SV-25193r1_rule'
  tag gtitle: 'Windows Installer – IE Security Prompt'
  tag fix_id: 'F-15551r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
