control 'SV-216771' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify the Interior Gateway Protocol (IGP) instance used for the managed network does not redistribute routes into the IGP instance used for the management network, and vice versa. The example below imports OSPF routes from the production route table (VRF PROD) into the management route table (VRF MGMT) using BGP.

vrf MGMT
 address-family ipv4 unicast
  import route-target
   4:4
   8:8
  !
  export route-target
   4:4
  !
 !
!
vrf PROD
 address-family ipv4 unicast
  import route-target
   8:8
  !
  export route-target
   8:8
  !
 !
!
…
…
…
router ospf 2
 vrf MGMT
  redistribute bgp 64512
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
router bgp 64512
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 vrf MGMT
  rd 4:4
  address-family ipv4 unicast
   redistribute ospf 2
  !
 !
 vrf PROD
  rd 8:8
  address-family ipv4 unicast
   redistribute ospf 3
  !
 !
!

If the IGP instance used for the managed network redistributes routes into the IGP instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Remove the configuration that imports routes from the managed network into the management network or vice versa as shown in the example below.

RP/0/0/CPU0:R2(config)#vrf MGMT
RP/0/0/CPU0:R2(config-vrf)#address-family ipv4 unicast 
RP/0/0/CPU0:R2(config-vrf-af)#no import route-target 8:8
RP/0/0/CPU0:R2(config-vrf-af)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18003r288696_chk'
  tag severity: 'medium'
  tag gid: 'V-216771'
  tag rid: 'SV-216771r531087_rule'
  tag stig_id: 'CISC-RT-000430'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-18001r288697_fix'
  tag 'documentable'
  tag legacy: ['SV-105887', 'V-96749']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
