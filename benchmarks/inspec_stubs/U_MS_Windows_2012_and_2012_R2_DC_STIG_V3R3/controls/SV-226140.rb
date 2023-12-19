control 'SV-226140' do
  title 'All Direct Access traffic must be routed through the internal network.'
  desc 'Routing all Direct Access  traffic through the internal network allows monitoring and prevents split tunneling.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: Force_Tunneling

Type: REG_SZ
Value: Enabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Route all traffic through the internal network" to "Enabled: Enabled State".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27842r475743_chk'
  tag severity: 'low'
  tag gid: 'V-226140'
  tag rid: 'SV-226140r794494_rule'
  tag stig_id: 'WN12-CC-000006'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27830r475744_fix'
  tag 'documentable'
  tag legacy: ['SV-53183', 'V-21961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
