control 'SV-48239' do
  title 'Remote access to the Plug and Play interface must be disabled for device installation.'
  desc 'Remote access to the Plug and Play interface could potentially allow connections by unauthorized devices.  This setting configures remote access to the Plug and Play interface and must be disabled.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: AllowRemoteRPC

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Allow remote access to the Plug and Play interface" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44918r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15700'
  tag rid: 'SV-48239r2_rule'
  tag stig_id: 'WN08-CC-000019'
  tag gtitle: 'Device Install – PnP Interface Remote Access'
  tag fix_id: 'F-41375r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
