control 'SV-16639' do
  title 'Device Install – PnP Interface Remote Access'
  desc 'This check verifies that remote access to the Plug and Play interface is disabled.'
  desc 'check', 'Vista/7 - If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name:  AllowRemoteRPC

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Vista -  Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Allow remote access to the PnP interface” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15388r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15700'
  tag rid: 'SV-16639r1_rule'
  tag gtitle: 'Device Install – PnP Interface Remote Access'
  tag fix_id: 'F-15592r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
