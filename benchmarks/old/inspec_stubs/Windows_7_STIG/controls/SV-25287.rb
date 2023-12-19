control 'SV-25287' do
  title 'Route all Direct Access  traffic through internal network.'
  desc 'This setting ensures all traffic is routed through the internal network, allowing monitoring and preventing split tunneling.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name:  Force_Tunneling

Type:  REG_SZ
Value:  Enabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> “Route all traffic through the internal network” to “Enabled: Enabled State”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26850r1_chk'
  tag severity: 'low'
  tag gid: 'V-21961'
  tag rid: 'SV-25287r1_rule'
  tag gtitle: 'Direct Access – Route Through Internal Network'
  tag fix_id: 'F-22949r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
