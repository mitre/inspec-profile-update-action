control 'SV-216680' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to have separate Interior Gateway Protocol (IGP) instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate IGP routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that the OOBM interface is an adjacency in the IGP domain for the management network via separate VRF as shown in the example below:

router ospf 1 vrf MGMT
 log-adjacency-changes
 network 0.0.0.0 255.255.255.255 area 0
!
router ospf 2 vrf PROD
 log-adjacency-changes
 network 0.0.0.0 255.255.255.255 area 0

If the router is not configured to have separate IGP instances for the managed network and management network, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to have a separate IGP instance for the management network as shown in the example below:

R3(config)#router ospf 1 vrf MGMT
R3(config-router)#network 0.0.0.0 0.0.0.0 area 0
R3(config-router)#exit
R3(config)#router ospf 2 vrf PROD
R3(config-router)#network 0.0.0.0 0.0.0.0 area 0
R3(config-router)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17913r287991_chk'
  tag severity: 'medium'
  tag gid: 'V-216680'
  tag rid: 'SV-216680r531086_rule'
  tag stig_id: 'CISC-RT-000420'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-17911r287992_fix'
  tag 'documentable'
  tag legacy: ['SV-106071', 'V-96933']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
