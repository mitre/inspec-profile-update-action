control 'SV-28517' do
  title 'Power Mgmt – Password Wake on Battery (Only applicable to 2008 if installed on a laptop.)'
  desc 'This check verifies that the user is prompted for a password on resume from sleep (on battery).'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name:  DCSettingIndex

Type:  REG_DWORD
Value:  1

This is only applicable on Server 2008 if it is installed on a laptop/mobile computer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings “Require a Password When a Computer Wakes (On Battery)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-28807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15705'
  tag rid: 'SV-28517r1_rule'
  tag gtitle: 'Power Mgmt – Password Wake on Battery'
  tag fix_id: 'F-15597r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
