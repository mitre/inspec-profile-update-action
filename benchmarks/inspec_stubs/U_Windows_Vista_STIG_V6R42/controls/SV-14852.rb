control 'SV-14852' do
  title 'User Account Control - Switch to secure desktop'
  desc 'This check verifies that the elevation prompt is only used in secure desktop mode.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Switch to the secure desktop when prompting for elevation” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  PromptOnSecureDesktop

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Switch to the secure desktop when prompting for elevation” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-32776r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14241'
  tag rid: 'SV-14852r1_rule'
  tag gtitle: 'UAC - Secure Desktop Mode'
  tag fix_id: 'F-28847r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
