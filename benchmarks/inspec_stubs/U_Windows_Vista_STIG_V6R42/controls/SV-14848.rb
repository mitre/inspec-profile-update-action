control 'SV-14848' do
  title 'User Account Control - Detect Application Installations'
  desc 'This check verifies whether Windows responds to application installation requests by prompting for credentials.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for “User Account Control: Detect application installations and prompt for elevation” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  EnableInstallerDetection

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Detect application installations and prompt for elevation” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-32772r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14237'
  tag rid: 'SV-14848r1_rule'
  tag gtitle: 'UAC - Application Installations'
  tag fix_id: 'F-28844r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
