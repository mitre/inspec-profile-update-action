control 'SV-205718' do
  title 'Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting requires Windows to respond to application installation requests by prompting for credentials.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableInstallerDetection

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Detect application installations and prompt for elevation" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5983r355072_chk'
  tag severity: 'medium'
  tag gid: 'V-205718'
  tag rid: 'SV-205718r569188_rule'
  tag stig_id: 'WN19-SO-000420'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-5983r355073_fix'
  tag 'documentable'
  tag legacy: ['SV-103611', 'V-93525']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
