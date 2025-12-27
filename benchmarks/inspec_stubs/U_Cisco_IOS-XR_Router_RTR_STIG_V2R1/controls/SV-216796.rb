control 'SV-216796' do
  title 'The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP) between two PE routers. Each MAC virtual forwarding table instance (VFI) is interconnected using pseudowires provisioned for the bridge domain, thereby maintaining privacy and logical separation between each VPLS bridge domain.

The VFI specifies the pseudowires associated with connecting PE routers and the customer-facing attachment circuits belonging to a given VLAN. Resembling a Layer 2 switch, the VFI is responsible for learning MAC addresses and providing loop-free forwarding of customer traffic to the appropriate end nodes. Each VPLS domain is identified by a globally unique VPN ID; hence, VFIs of the same VPLS domain must be configured with the same VPN ID on all participating PE routers. To guarantee traffic separation for all customer VLANs and that all packets are forwarded to the correct destination, it is imperative that the correct attachment circuits are associated with the appropriate VFI and that each VFI is associated to the unique VPN ID assigned to the customer VLAN.'
  desc 'check', 'Review the implementation plan and the VPN IDs assigned to customer VLANs for the VPLS deployment.

Review the PE router configuration to verify that customer attachment circuits are associated to the appropriate VFI. In the example below, the attached circuit at  interface GigabitEthernet0/0/0/2 is associated to VPN ID 110.

interface GigabitEthernet0/0/0/2
 l2transport
…
…
…
l2vpn
 pw-class ETH_O_MPLS
  encapsulation mpls
   transport-mode ethernet
  !
 !
 bridge group L2GROUP
  bridge-domain L2_BRIDGE_COI1
   interface GigabitEthernet0/0/0/2
   !
   vfi VFI_COI1
    vpn-id 101
    neighbor 10.1.1.1 pw-id 55
     pw-class ETH_O_MPLS
    !
    neighbor 10.2.2.2 pw-id 55
     pw-class ETH_O_MPLS
    !
   !
  !
 !

If the attachment circuits have not been bound to VFI configured with the assigned VPN ID for each VLAN, this is a finding.'
  desc 'fix', 'Assign globally unique VPN IDs for each customer using VPLS for carrier Ethernet services between multiple sites, and configure the attachment circuits to the appropriate VFI.

RP/0/0/CPU0:R3(config)#l2vpn
RP/0/0/CPU0:R3(config-l2vpn)#bridge group L2GROUP
RP/0/0/CPU0:R3(config-l2vpn-bg)#bridge-domain L2_BRIDGE_COI1
RP/0/0/CPU0:R3(config-l2vpn-bg-bd)#interface GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#exit
RP/0/0/CPU0:R3(config-l2vpn-bg-bd)#vfi VFI_COI1
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-vfi)#vpn-id 101'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18028r288765_chk'
  tag severity: 'high'
  tag gid: 'V-216796'
  tag rid: 'SV-216796r531087_rule'
  tag stig_id: 'CISC-RT-000680'
  tag gtitle: 'SRG-NET-000512-RTR-000009'
  tag fix_id: 'F-18026r288766_fix'
  tag 'documentable'
  tag legacy: ['SV-105937', 'V-96799']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
