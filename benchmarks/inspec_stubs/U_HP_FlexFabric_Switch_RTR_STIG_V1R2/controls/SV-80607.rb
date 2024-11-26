control 'SV-80607' do
  title 'The HP FlexFabric Switch must enforce that the managed network domain and the management network domain are separate routing domains and the Interior Gateway Protocol (IGP) instances are not redistributed or advertised to each other.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, several safeguards must be implemented for containment of management and production traffic boundaries, otherwise, it is possible that management traffic will not be separated from production traffic. 

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the out-of-band management network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'Review the configuration to verify the management interface belongs to a different OSPF instance (process) than the production network. If the management interface does not belong to a different OSPF instance, this is a finding.'
  desc 'fix', 'If OSPF is used for the management network, configure the management interface to belong to a different OSPF instance than the production network.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66117'
  tag rid: 'SV-80607r1_rule'
  tag stig_id: 'HFFS-RT-000015'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-72193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
