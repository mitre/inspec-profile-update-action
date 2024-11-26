control 'SV-32474' do
  title 'Errors in handwriting recognition on Tablet PCs will not be reported to Microsoft.'
  desc 'This check verifies that errors in handwriting recognition on Tablet PCs are not reported to Microsoft.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports\\

Value Name:  PreventHandwritingErrorReports

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communications settings “Turn off handwriting recognition error reporting” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15392r1_chk'
  tag severity: 'low'
  tag gid: 'V-15704'
  tag rid: 'SV-32474r1_rule'
  tag gtitle: 'Handwriting Recognition Error Reporting'
  tag fix_id: 'F-15596r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
