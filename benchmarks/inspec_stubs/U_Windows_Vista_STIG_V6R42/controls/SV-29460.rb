control 'SV-29460' do
  title 'Media Player – First Use Dialog Boxes'
  desc 'This check verifies that users are not presented with Privacy and Installation options on first use of Windows Media Player.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name:  GroupPrivacyAcceptance

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player “Do Not Show First Use Dialog Boxes” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15331r1_chk'
  tag severity: 'low'
  tag gid: 'V-15687'
  tag rid: 'SV-29460r1_rule'
  tag gtitle: 'Media Player – First Use Dialog Boxes'
  tag fix_id: 'F-15554r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
