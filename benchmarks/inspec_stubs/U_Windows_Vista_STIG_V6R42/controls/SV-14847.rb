control 'SV-14847' do
  title 'User Account Control - Behavior of elevation prompt for standard users.'
  desc 'This check verifies whether the logged on user is prompted for credentials when attempting to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Behavior of the elevation prompt for standard users” is not set to “Prompt for credentials”, then this is a finding.

The policy referenced configures the following registry value:

Registry Path: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ConsentPromptBehaviorUser

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Behavior of the elevation prompt for standard users”  to “Prompt for credentials”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-28793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14236'
  tag rid: 'SV-14847r1_rule'
  tag gtitle: 'UAC - User Elevation Prompt'
  tag fix_id: 'F-13561r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
