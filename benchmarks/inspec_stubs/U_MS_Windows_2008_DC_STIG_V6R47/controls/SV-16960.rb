control 'SV-16960' do
  title 'UAC - Application Elevations'
  desc 'This check verifies that Windows elevates all applications, not just signed ones.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Only elevate executables that are signed and validated” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ValidateAdminCodeSignatures

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Only elevate executables that are signed and validated” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16008'
  tag rid: 'SV-16960r1_rule'
  tag gtitle: 'UAC - Application Elevations'
  tag fix_id: 'F-28963r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
