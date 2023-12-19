control 'SV-216681' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol (IGP) routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify the IGP instance used for the managed network does not redistribute routes into the IGP instance used for the management network, and vice versa. The example below imports OSPF routes from the production route table (VRF PROD) into the management route table (VRF MGMT) using BGP.

ip vrf MGMT
 rd 4:4
 route-target export 4:4
 route-target import 4:4
 route-target import 8:8
!
ip vrf PROD
 rd 8:8
 route-target import 8:8
 route-target export 8:8
…
…
…
router ospf 1 vrf MGMT
 log-adjacency-changes
 redistribute bgp 64512 subnets
 network 0.0.0.0 255.255.255.255 area 0
!
router ospf 2 vrf PROD
 log-adjacency-changes
 network 0.0.0.0 255.255.255.255 area 0
!
router bgp 64512
 no synchronization
 bgp log-neighbor-changes
 no auto-summary
 !
 address-family ipv4 vrf MGMT
  no synchronization
  redistribute ospf 1 vrf MGMT
 exit-address-family
 !
 address-family ipv4 vrf PROD
  no synchronization
  redistribute ospf 2 vrf PROD
 exit-address-family

If the IGP instance used for the managed network redistributes routes into the IGP instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Remove the configuration that imports routes from the managed network into the management network or vice versa as shown in the example below:

R1(config)#ip vrf MGMT
R1(config-vrf)#no route-target import 8:8'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17914r287994_chk'
  tag severity: 'medium'
  tag gid: 'V-216681'
  tag rid: 'SV-216681r531086_rule'
  tag stig_id: 'CISC-RT-000430'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-17912r287995_fix'
  tag 'documentable'
  tag legacy: ['SV-106073', 'V-96935']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
