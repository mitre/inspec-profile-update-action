control 'SV-25124' do
  title 'User Account Control - Non UAC compliant applications run in virtualized file and registry entries.'
  desc 'This check verifies that non UAC compliant applications will run in virtualized file and registry entries in per user locations allowing them to run.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Virtualize file and registry write failures to per-user locations” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  EnableVirtualization

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Virtualize file and registry write failures to per-user locations” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-32777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14242'
  tag rid: 'SV-25124r1_rule'
  tag gtitle: 'UAC - Non UAC Compliant Application Virtualization'
  tag fix_id: 'F-28848r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
