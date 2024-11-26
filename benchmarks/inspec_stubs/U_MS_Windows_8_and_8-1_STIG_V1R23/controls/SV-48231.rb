control 'SV-48231' do
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Users must be aware of attempted program installations.  This setting ensures users are notified if a web-based program attempts to install software.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44910r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15684'
  tag rid: 'SV-48231r1_rule'
  tag stig_id: 'WN08-CC-000117'
  tag gtitle: 'Windows Installer – IE Security Prompt'
  tag fix_id: 'F-41367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
