control 'SV-225063' do
  title 'User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 0x00000002 (2) (Prompt for consent on the secure desktop)
0x00000001 (1) (Prompt for credentials on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent on the secure desktop".

The more secure option for this setting, "Prompt for credentials on the secure desktop", would also be acceptable.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26754r466091_chk'
  tag severity: 'medium'
  tag gid: 'V-225063'
  tag rid: 'SV-225063r569186_rule'
  tag stig_id: 'WN16-SO-000480'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-26742r466092_fix'
  tag 'documentable'
  tag legacy: ['SV-88375', 'V-73711']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
