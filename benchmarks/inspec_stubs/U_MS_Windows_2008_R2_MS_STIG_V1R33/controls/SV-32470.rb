control 'SV-32470' do
  title 'Remote access to the Plug and Play interface will be disabled for device installation.'
  desc 'This check verifies that remote access to the Plug and Play interface is disabled.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\ 

Value Name: AllowRemoteRPC 

Type: REG_DWORD 
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Allow remote access to the Plug and Play interface” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15700'
  tag rid: 'SV-32470r1_rule'
  tag gtitle: 'Device Install – PnP Interface Remote Access'
  tag fix_id: 'F-28863r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
