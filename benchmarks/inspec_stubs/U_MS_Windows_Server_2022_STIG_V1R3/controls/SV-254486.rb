control 'SV-254486' do
  title 'Windows Server 2022 User Account Control (UAC) must be configured to detect application installations and prompt for elevation.'
  desc 'UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting requires Windows to respond to application installation requests by prompting for credentials.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2022 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableInstallerDetection

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> User Account Control: Detect application installations and prompt for elevation to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57971r849272_chk'
  tag severity: 'medium'
  tag gid: 'V-254486'
  tag rid: 'SV-254486r849274_rule'
  tag stig_id: 'WN22-SO-000420'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-57922r849273_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
