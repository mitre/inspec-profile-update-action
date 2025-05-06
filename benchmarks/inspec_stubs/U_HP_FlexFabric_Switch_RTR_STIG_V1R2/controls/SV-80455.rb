control 'SV-80455' do
  title 'The HP FlexFabric Switch must be configured so inactive HP FlexFabric Switch interfaces are disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.'
  desc 'check', 'Review the network topology diagram and determine which HP FlexFabric Switch interfaces should be inactive.

If there are inactive HP FlexFabric Switch interfaces that are enabled, this is a finding.

[HP]display current-configuration interface
interface GigabitEthernet0/1
 port link-mode route
 pim sm
 ip address 192.168.10.1 255.255.255.0
 packet-filter 3010 inbound'
  desc 'fix', 'Disable inactive the HP FlexFabric Switch interface:

[HP-GigabitEthernet0/1] shutdown'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65965'
  tag rid: 'SV-80455r1_rule'
  tag stig_id: 'HFFS-RT-000001'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-72041r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
