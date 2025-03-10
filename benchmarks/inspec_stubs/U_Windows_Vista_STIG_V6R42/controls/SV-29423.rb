control 'SV-29423' do
  title 'Computer prevented from downloading print driver packages over HTTP.'
  desc 'This check verifies that the system is configured to prevent the computer from downloading print driver packages over HTTP.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Printers

Value Name:  DisableWebPnPDownload

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off downloading of print drivers over HTTP’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-11607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14260'
  tag rid: 'SV-29423r1_rule'
  tag gtitle: 'HTTP Printer Drivers'
  tag fix_id: 'F-13585r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
