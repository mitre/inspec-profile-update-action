control 'SV-253469' do
  title 'User Account Control must prompt administrators for consent on the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 2 (Prompt for consent on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent on the secure desktop".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56922r829489_chk'
  tag severity: 'medium'
  tag gid: 'V-253469'
  tag rid: 'SV-253469r829491_rule'
  tag stig_id: 'WN11-SO-000250'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-56872r829490_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
