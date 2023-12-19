control 'SV-205719' do
  title 'Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations.'
  desc 'UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\\System32 folders, to run with elevated privileges.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableSecureUIAPaths

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5984r355075_chk'
  tag severity: 'medium'
  tag gid: 'V-205719'
  tag rid: 'SV-205719r569188_rule'
  tag stig_id: 'WN19-SO-000430'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-5984r355076_fix'
  tag 'documentable'
  tag legacy: ['V-93527', 'SV-103613']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
