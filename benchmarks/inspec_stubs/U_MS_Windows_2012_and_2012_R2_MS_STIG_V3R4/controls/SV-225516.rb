control 'SV-225516' do
  title 'User Account Control must, at minimum, prompt administrators for consent.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 4 (Prompt for consent)
3 (Prompt for credentials)
2 (Prompt for consent on the secure desktop)
1 (Prompt for credentials on the secure desktop)'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".

More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27215r471890_chk'
  tag severity: 'medium'
  tag gid: 'V-225516'
  tag rid: 'SV-225516r569185_rule'
  tag stig_id: 'WN12-SO-000078'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27203r471891_fix'
  tag 'documentable'
  tag legacy: ['V-14235', 'SV-52947']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
