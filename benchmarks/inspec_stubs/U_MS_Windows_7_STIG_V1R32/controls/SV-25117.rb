control 'SV-25117' do
  title 'User Account Control is configured for the appropriate elevation prompt for administrators'
  desc 'This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode” is not set to “Prompt for consent on the secure desktop”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ConsentPromptBehaviorAdmin

Value Type:  REG_DWORD
Value:  2 (Prompt for consent on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode” to “Prompt for consent on the secure desktop”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14235'
  tag rid: 'SV-25117r1_rule'
  tag gtitle: 'UAC - Admin Elevation Prompt'
  tag fix_id: 'F-22902r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
