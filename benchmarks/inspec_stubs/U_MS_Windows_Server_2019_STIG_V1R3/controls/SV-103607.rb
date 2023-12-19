control 'SV-103607' do
  title 'Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableUIADesktopToggle

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93521'
  tag rid: 'SV-103607r1_rule'
  tag stig_id: 'WN19-SO-000390'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-99765r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
