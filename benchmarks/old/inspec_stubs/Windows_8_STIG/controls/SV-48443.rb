control 'SV-48443' do
  title 'All Direct Access traffic must be routed through the internal network.'
  desc 'Routing all Direct Access  traffic through the internal network allows monitoring and prevents split tunneling.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: Force_Tunneling

Type: REG_SZ
Value: Enabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Route all traffic through the internal network" to "Enabled: Enabled State".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45107r2_chk'
  tag severity: 'low'
  tag gid: 'V-21961'
  tag rid: 'SV-48443r2_rule'
  tag stig_id: 'WN08-CC-000006'
  tag gtitle: 'Direct Access – Route Through Internal Network'
  tag fix_id: 'F-41571r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
