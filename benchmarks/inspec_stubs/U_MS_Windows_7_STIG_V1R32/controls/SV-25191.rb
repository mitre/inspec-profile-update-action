control 'SV-25191' do
  title 'Disable heap termination on corruption in Windows Explorer.'
  desc 'This check verifies that heap termination on corruption is disabled.  This may prevent Windows Explorer from terminating immediately from certain legacy plug-in applications.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name:  NoHeapTerminationOnCorruption

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Explorer “Turn off heap termination on corruption” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15406r1_chk'
  tag severity: 'low'
  tag gid: 'V-15718'
  tag rid: 'SV-25191r2_rule'
  tag gtitle: 'Windows Explorer – Heap Termination'
  tag fix_id: 'F-15610r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
