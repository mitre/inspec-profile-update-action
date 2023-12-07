control 'SV-225066' do
  title 'User Account Control must only elevate UIAccess applications that are installed in secure locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\\System32 folders, to run with elevated privileges.'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableSecureUIAPaths

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26757r466100_chk'
  tag severity: 'medium'
  tag gid: 'V-225066'
  tag rid: 'SV-225066r569186_rule'
  tag stig_id: 'WN16-SO-000510'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-26745r466101_fix'
  tag 'documentable'
  tag legacy: ['SV-88381', 'V-73717']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
