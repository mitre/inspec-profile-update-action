control 'SV-29614' do
  title 'Order Prints Online'
  desc 'This check verifies that the “Order Prints Online” task is not available in Windows Explorer.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoOnlinePrintsWizard

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off the “Order Prints” picture task” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15320r1_chk'
  tag severity: 'low'
  tag gid: 'V-15676'
  tag rid: 'SV-29614r1_rule'
  tag gtitle: 'Order Prints Online'
  tag fix_id: 'F-15543r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
