control 'SV-25145' do
  title 'Disable remote access to the plug and play interface.'
  desc 'This check verifies that remote access to the Plug and Play interface is disabled.'
  desc 'check', 'Vista/7 - If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name:  AllowRemoteRPC

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Allow remote access to the Plug and Play interface” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-15388r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15700'
  tag rid: 'SV-25145r1_rule'
  tag gtitle: 'Device Install – PnP Interface Remote Access'
  tag fix_id: 'F-22909r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
