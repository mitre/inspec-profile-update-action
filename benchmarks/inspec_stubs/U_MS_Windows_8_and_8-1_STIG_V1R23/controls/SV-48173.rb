control 'SV-48173' do
  title 'User Account Control must, at minimum, prompt administrators for consent on the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" is not set to "Prompt for consent on the secure desktop", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 2 (Prompt for consent on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent on the secure desktop".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14235'
  tag rid: 'SV-48173r2_rule'
  tag stig_id: 'WN08-SO-000078'
  tag gtitle: 'UAC - Admin Elevation Prompt'
  tag fix_id: 'F-41311r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
