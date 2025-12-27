control 'SV-216770' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that the OOBM interface is an adjacency in the IGP domain for the management network via separate VRF as shown in the example below.

router ospf 2
 vrf MGMT
  area 0
   interface GigabitEthernet0/0/0/0.2
   !
  !
 !
!
router ospf 3
 vrf PROD
  area 0
   interface GigabitEthernet0/0/0/0.3
   !
  !
 !
!

If the router is not configured to have separate IGP instances for the managed network and management network, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to have a separate IGP instance for the management network as shown in the example below.

RP/0/0/CPU0:R2(config)#router ospf 2 vrf MGMT
RP/0/0/CPU0:R2(config-ospf-vrf)#area 0
RP/0/0/CPU0:R2(config-ospf-vrf-ar)#interface GigabitEthernet0/0/0/0.2
RP/0/0/CPU0:R2(config-ospf-vrf-ar-if)#exit
RP/0/0/CPU0:R2(config-ospf-vrf-ar)#exit
RP/0/0/CPU0:R2(config-ospf-vrf)#exit
RP/0/0/CPU0:R2(config-ospf)#exit
RP/0/0/CPU0:R2(config)#router ospf 3 vrf PROD
RP/0/0/CPU0:R2(config-ospf-vrf)#area 0
RP/0/0/CPU0:R2(config-ospf-vrf-ar)#interface GigabitEthernet0/0/0/0.3
RP/0/0/CPU0:R2(config-ospf-vrf-ar-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18002r288693_chk'
  tag severity: 'medium'
  tag gid: 'V-216770'
  tag rid: 'SV-216770r531087_rule'
  tag stig_id: 'CISC-RT-000420'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-18000r288694_fix'
  tag 'documentable'
  tag legacy: ['SV-105885', 'V-96747']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
