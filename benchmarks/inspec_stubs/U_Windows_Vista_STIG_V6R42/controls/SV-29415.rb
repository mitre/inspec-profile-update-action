control 'SV-29415' do
  title 'Web Publishing and online ordering wizards prevented from downloading list of providers.'
  desc 'This check verifies that the system is configured to prevent Windows from downloading a list of providers for the Web publishing and online ordering wizards.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Value Name:  NoWebServices

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off Internet download for Web publishing and online ordering wizards’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11602r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14256'
  tag rid: 'SV-29415r1_rule'
  tag gtitle: 'Internet Download / Online Ordering'
  tag fix_id: 'F-13581r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
