control 'SV-80605' do
  title 'The HP FlexFabric Switch must enforce that Interior Gateway Protocol (IGP) instances configured on the out-of-band management gateway only peer with their own routing domain.'
  desc 'If the gateway router is not a dedicated device for the out-of-band management network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'Review the configuration to verify the management interface belongs to a different OSPF instance (process) than the production network. If the management interface does not belong to a different OSPF instance, this is a finding.'
  desc 'fix', 'If OSPF is used for the management network, configure the management interface to belong to a different OSPF instance than the production network.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66115'
  tag rid: 'SV-80605r1_rule'
  tag stig_id: 'HFFS-RT-000014'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-72191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
