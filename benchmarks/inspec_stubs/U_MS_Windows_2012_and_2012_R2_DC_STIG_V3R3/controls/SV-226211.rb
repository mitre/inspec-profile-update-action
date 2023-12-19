control 'SV-226211' do
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Users must be aware of attempted program installations.  This setting ensures users are notified if a web-based program attempts to install software.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27913r475956_chk'
  tag severity: 'medium'
  tag gid: 'V-226211'
  tag rid: 'SV-226211r794505_rule'
  tag stig_id: 'WN12-CC-000117'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27901r475957_fix'
  tag 'documentable'
  tag legacy: ['SV-53056', 'V-15684']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
