control 'SV-48462' do
  title 'Changing the screen saver must be prevented.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Preventing users from changing the screen saver ensures an approved screen saver is used.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: NoDispScrSavPage

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Prevent changing screen saver" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45126r1_chk'
  tag severity: 'low'
  tag gid: 'V-36775'
  tag rid: 'SV-48462r2_rule'
  tag stig_id: 'WN08-UC-000004'
  tag gtitle: 'WINUC-000004'
  tag fix_id: 'F-41589r1_fix'
  tag 'documentable'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
