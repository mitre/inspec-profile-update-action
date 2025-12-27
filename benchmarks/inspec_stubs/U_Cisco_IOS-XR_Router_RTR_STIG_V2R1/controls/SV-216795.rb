control 'SV-216795' do
  title 'The Cisco PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate pseudowire ID for each attachment circuit.'
  desc 'VPWS is an L2VPN technology that provides a virtual circuit (aka pseudowire) between two PE routers to forward Layer 2 frames between two customer-edge routers or switches through an MPLS-enabled IP core. The ingress PE router (virtual circuit head-end) encapsulates Ethernet frames inside MPLS packets using label stacking and forwards them across the MPLS network to the egress PE router (virtual circuit tail-end). During a virtual circuit setup, the PE routers exchange label bindings for the specified pseudowire ID. The pseudowire ID specifies a pseudowire associated with an ingress and egress PE router and the customer-facing attachment circuits. 

To guarantee that all frames are forwarded onto the correct pseudowire and to the correct customer and attachment circuits, it is imperative that the correct pseudowire ID is configured for each attachment circuit.'
  desc 'check', 'Verify that the correct pseudowire ID has been configured for the appropriate attachment circuit. In the example below GigabitEthernet0/0/0/1 is the CE-facing interface that is configured for VPWS.

l2vpn
 pw-class ETHOM
  encapsulation mpls
  !
 !
 xconnect group COI1
  p2p COI1-S1-S2
   interface GigabitEthernet0/0/0/1
   neighbor ipv4 10.1.12.4 pw-id 55
    pw-class ETHOM
   !
  !
 !
!

If the correct pseudowire ID has not been configured on both routers, this is a finding.'
  desc 'fix', 'Assign globally unique pseudowire IDs for each virtual circuit and configure the attachment circuits with the appropriate pseudowire ID.  

RP/0/0/CPU0:R3(config)#l2vpn
RP/0/0/CPU0:R3(config-l2vpn)#xconnect group COI1 
RP/0/0/CPU0:R3(config-l2vpn-xc)#p2p COI1-S1-S2
RP/0/0/CPU0:R3(config-l2vpn-xc-p2p)#interface g0/0/0/1
RP/0/0/CPU0:R3(config-l2vpn-xc-p2p)#neighbor 10.1.12.4 pw-id 55'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18027r288762_chk'
  tag severity: 'high'
  tag gid: 'V-216795'
  tag rid: 'SV-216795r531087_rule'
  tag stig_id: 'CISC-RT-000670'
  tag gtitle: 'SRG-NET-000512-RTR-000008'
  tag fix_id: 'F-18025r288763_fix'
  tag 'documentable'
  tag legacy: ['V-96797', 'SV-105935']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
