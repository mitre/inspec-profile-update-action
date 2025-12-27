control 'SV-216590' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that the OOBM interface is an adjacency in the IGP domain for the management network via separate VRF as shown in the example below.

router ospf 1 vrf MGMT
 log-adjacency-changes
 network 0.0.0.0 255.255.255.255 area 0
!
router ospf 2 vrf PROD
 log-adjacency-changes
 network 0.0.0.0 255.255.255.255 area 0

If the router is not configured to have separate IGP instances for the managed network and management network, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to have a separate IGP instance for the management network as shown in the example below.

R3(config)#router ospf 1 vrf MGMT
R3(config-router)#network 0.0.0.0 0.0.0.0 area 0
R3(config-router)#exit
R3(config)#router ospf 2 vrf PROD
R3(config-router)#network 0.0.0.0 0.0.0.0 area 0
R3(config-router)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17825r287148_chk'
  tag severity: 'medium'
  tag gid: 'V-216590'
  tag rid: 'SV-216590r531085_rule'
  tag stig_id: 'CISC-RT-000420'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-17821r287149_fix'
  tag 'documentable'
  tag legacy: ['SV-105719', 'V-96581']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
