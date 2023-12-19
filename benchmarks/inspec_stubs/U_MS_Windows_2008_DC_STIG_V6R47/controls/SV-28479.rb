control 'SV-28479' do
  title 'User Account Control - Behavior of elevation prompt for standard users.'
  desc 'This check verifies that standard users are automatically denied when attempting to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for “User Account Control: Behavior of the elevation prompt for standard users” is not set to “Automatically deny elevation requests”, then this is a finding.

The policy referenced configures the following registry value:

Registry Path: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:	ConsentPromptBehaviorUser

Value Type:	REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Behavior of the elevation prompt for standard users” to “Automatically deny elevation requests”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-28791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14236'
  tag rid: 'SV-28479r1_rule'
  tag gtitle: 'UAC - User Elevation Prompt'
  tag fix_id: 'F-28843r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
