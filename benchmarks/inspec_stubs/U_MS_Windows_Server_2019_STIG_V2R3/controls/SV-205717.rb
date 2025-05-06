control 'SV-205717' do
  title 'Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is default installation option for Windows Server 2019 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 0x00000002 (2) (Prompt for consent on the secure desktop)
0x00000001 (1) (Prompt for credentials on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent on the secure desktop".

The more secure option for this setting, "Prompt for credentials on the secure desktop", would also be acceptable.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5982r355069_chk'
  tag severity: 'medium'
  tag gid: 'V-205717'
  tag rid: 'SV-205717r569188_rule'
  tag stig_id: 'WN19-SO-000400'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-5982r355070_fix'
  tag 'documentable'
  tag legacy: ['SV-103609', 'V-93523']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
