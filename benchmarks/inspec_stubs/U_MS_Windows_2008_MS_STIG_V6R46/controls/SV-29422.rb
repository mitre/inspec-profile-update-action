control 'SV-29422' do
  title 'Prevent printing over HTTP.'
  desc 'This check verifies that the system is configured to prevent the client computer’s ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Printers

Value Name:  DisableHTTPPrinting

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off printing over HTTP’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-11606r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14259'
  tag rid: 'SV-29422r1_rule'
  tag gtitle: 'Printing Over HTTP'
  tag fix_id: 'F-13584r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
