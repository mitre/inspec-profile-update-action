control 'SV-256055' do
  title 'The PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.'
  desc 'VPWS is an L2VPN technology that provides a virtual circuit between two PE routers to forward Layer 2 frames between two customer-edge routers or routers through an MPLS-enabled IP core. The ingress PE router (virtual circuit head-end) encapsulates Ethernet frames inside MPLS packets using label stacking and forwards them across the MPLS network to the egress PE router (virtual circuit tail-end). During a virtual circuit setup, the PE routers exchange VC label bindings for the specified VC ID. The VC ID specifies a pseudowire associated with an ingress and egress PE router and the customer-facing attachment circuits.

To guarantee that all frames are forwarded onto the correct pseudowire and to the correct customer and attachment circuits, it is imperative that the correct VC ID is configured for each attachment circuit.'
  desc 'check', 'Review the ingress and egress PE router configuration for each virtual circuit that has been provisioned.

Verify the correct and unique VCID has been configured for the appropriate attachment circuit.

Run the command sh run | section patch
patch panel
   patch port
      connector 1 interface Ethernet2
      connector 2 pseudowire bgp vpws evi-1 pseudowire pw1
   patch subintf
      connector 1 interface Ethernet3.1
      connector 2 pseudowire bgp vpws evi-1 pseudowire pw2

Run the command sh run | section router bgp          
router bgp 65000
   neighbor 10.0.0.1 remote-as 1
   neighbor 10.0.0.1 send-community extended
   neighbor 10.0.0.1 maximum-routes 12000
   !
   vpws evi-1
      rd 10.2.2.2:2
      route-target import export evpn 0.0.0.0:1
      mpls control-word
      !
      pseudowire pw1
         evpn vpws id local 2001 remote 1001
      !
      pseudowire pw2
         evpn vpws id local 2002 remote 1002
   !
   address-family evpn
      neighbor default encapsulation mpls next-hop-self source-interface Loopback0
      neighbor 10.0.0.1 activate

If the correct VC ID has not been configured on both routers, this is a finding.'
  desc 'fix', 'Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID.

Configure the same VC ID on both ends of the VC.

patch panel
   patch port
      connector 1 interface Ethernet2
      connector 2 pseudowire bgp vpws evi-1 pseudowire pw1
   patch subintf
      connector 1 interface Ethernet3.1
      connector 2 pseudowire bgp vpws evi-1 pseudowire pw2
          
router bgp 65000
   neighbor 10.0.0.1 remote-as 1
   neighbor 10.0.0.1 send-community extended
   neighbor 10.0.0.1 maximum-routes 12000
   !
   vpws evi-1
      rd 10.2.2.2:2
      route-target import export evpn 0.0.0.0:1
      mpls control-word
      !
      pseudowire pw1
         evpn vpws id local 2001 remote 1001
      !
      pseudowire pw2
         evpn vpws id local 2002 remote 1002
   !
   address-family evpn
      neighbor default encapsulation mpls next-hop-self source-interface Loopback0
      neighbor 10.0.0.1 activate
                    
VLAN mode example:

interface Ethernet3
   no routerport
!   
interface Ethernet3.1
   encapsulation dot1q vlan 1
      
Flexible Encapsulation example:

interface Ethernet3
   no routerport
!   
interface Ethernet3.1
   encapsulation vlan
      client dot1q 11 network client'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59731r882505_chk'
  tag severity: 'high'
  tag gid: 'V-256055'
  tag rid: 'SV-256055r882507_rule'
  tag stig_id: 'ARST-RT-000760'
  tag gtitle: 'SRG-NET-000512-RTR-000008'
  tag fix_id: 'F-59674r882506_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
