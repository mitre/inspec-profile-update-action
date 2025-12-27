control 'SV-225391' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27090r471515_chk'
  tag severity: 'medium'
  tag gid: 'V-225391'
  tag rid: 'SV-225391r569185_rule'
  tag stig_id: 'WN12-CC-000117'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27078r471516_fix'
  tag 'documentable'
  tag legacy: ['SV-53056', 'V-15684']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
