control 'SV-32377' do
  title 'User Account Control will, at a minimum, prompt administrators for consent.'
  desc 'This check verifies whether logged on administrator is prompted for consent when attempting to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode” is not set to “Prompt for consent”, then this is a finding.

More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop).

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ConsentPromptBehaviorAdmin

Value Type:  REG_DWORD
Value:  4 (Prompt for consent)
             3 (Prompt for credentials)
             2 (Prompt for consent on the secure desktop)
             1 (Prompt for credentials on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode” to “Prompt for consent”.

Note: More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14235'
  tag rid: 'SV-32377r1_rule'
  tag gtitle: 'UAC - Admin Elevation Prompt'
  tag fix_id: 'F-28842r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
