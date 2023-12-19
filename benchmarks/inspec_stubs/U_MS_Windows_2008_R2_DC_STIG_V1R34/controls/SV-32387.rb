control 'SV-32387' do
  title 'User Account Control will run all administrators in Admin Approval Mode, enabling UAC.'
  desc 'This check verifies that UAC has not been disabled.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Run all administrators in Admin Approval Mode” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  EnableLUA

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Run all administrators in Admin Approval Mode” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14240'
  tag rid: 'SV-32387r1_rule'
  tag gtitle: 'UAC - All Admin Approval Mode'
  tag fix_id: 'F-28846r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
