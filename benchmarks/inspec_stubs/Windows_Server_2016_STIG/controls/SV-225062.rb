control 'SV-225062' do
  title 'UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableUIADesktopToggle

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26753r466088_chk'
  tag severity: 'medium'
  tag gid: 'V-225062'
  tag rid: 'SV-225062r569186_rule'
  tag stig_id: 'WN16-SO-000470'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-26741r466089_fix'
  tag 'documentable'
  tag legacy: ['V-73709', 'SV-88373']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
