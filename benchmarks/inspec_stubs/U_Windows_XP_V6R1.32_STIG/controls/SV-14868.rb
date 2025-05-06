control 'SV-14868' do
  title 'Windows Messenger prevented from collecting anonymous information.'
  desc 'This check verifies that the system is configured to prevent Windows Messenger from collecting anonymous information about how the Windows Messenger software and service is used.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Messenger\\Client

Value Name:  CEIP

Type:  REG_DWORD
Value:  2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off the Windows Messenger Customer Experience Improvement Program’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-11604r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14257'
  tag rid: 'SV-14868r1_rule'
  tag gtitle: 'Windows Messenger Experience Improvement'
  tag fix_id: 'F-13582r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
