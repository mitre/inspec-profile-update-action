control 'SV-14846' do
  title 'User Account Control must, at minimum, prompt administrators for consent.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" is not set to "Prompt for consent", this is a finding.

More secure options for this setting are also acceptable (e.g., Prompt for credentials).

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 2 (Prompt for consent)
1 (Prompt for credentials)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".

More secure options for this setting are also acceptable (e.g., Prompt for credentials).'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-45830r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14235'
  tag rid: 'SV-14846r2_rule'
  tag gtitle: 'UAC - Admin Elevation Prompt'
  tag fix_id: 'F-43222r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
