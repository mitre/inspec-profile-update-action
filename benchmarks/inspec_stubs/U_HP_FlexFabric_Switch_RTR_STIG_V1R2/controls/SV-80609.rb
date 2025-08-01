control 'SV-80609' do
  title 'The HP FlexFabric Switch must enforce that any interface used for out-of-band management traffic is configured to be passive for the Interior Gateway Protocol (IGP) that is utilized on that management interface.'
  desc 'The out-of-band management access switch will connect to the management interface of the managed network elements. The management interface can be a true out-of-band management interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will directly connect to the out-of-band management network.

An out-of-band management interface does not forward transit traffic, thereby, providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an out-of-band management port, the interface functioning as the management interface must be configured so that management traffic, both data plane and control plane, does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Review the configuration to verify the OOBM  interface belongs to a different OSPF instance (process) than the production network. If the management interface does not belong to a different OSPF instance, this is a finding.
Note: By default an OOBM interface is passive to a routing protocol.'
  desc 'fix', 'If OSPF is used for the management network, configure the OOBM interface to belong to a different OSPF instance than the production network.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66119'
  tag rid: 'SV-80609r1_rule'
  tag stig_id: 'HFFS-RT-000016'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-72195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
