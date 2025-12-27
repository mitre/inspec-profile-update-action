control 'SV-216706' do
  title 'The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP) between two PE routers. Each MAC virtual forwarding table instance (VFI) is interconnected using pseudowires provisioned for the bridge domain, thereby maintaining privacy and logical separation between each VPLS bridge domain.

The VFI specifies the pseudowires associated with connecting PE routers and the customer-facing attachment circuits belonging to a given VLAN. Resembling a Layer 2 switch, the VFI is responsible for learning MAC addresses and providing loop-free forwarding of customer traffic to the appropriate end nodes. Each VPLS domain is identified by a globally unique VPN ID; hence, VFIs of the same VPLS domain must be configured with the same VPN ID on all participating PE routers. To guarantee traffic separation for all customer VLANs and that all packets are forwarded to the correct destination, it is imperative that the correct attachment circuits are associated with the appropriate VFI and that each VFI is associated to the unique VPN ID assigned to the customer VLAN.'
  desc 'check', 'Review the implementation plan and the VPN IDs assigned to customer VLANs for the VPLS deployment.

Review the PE router configuration to verify that customer attachment circuits are associated to the appropriate VFI. In the example below, the attached circuit at interface GigabitEthernet3 is associated to VPN ID 110.

l2 vfi VPLS_A manual 
 vpn id 110
 bridge-domain 100
 neighbor 10.3.3.3 encapsulation mpls
 neighbor 10.3.3.4 encapsulation mpls
…
…
…
interface GigabitEthernet3
 no ip address
 service instance 10 ethernet
  encapsulation untagged
  bridge-domain 100

If the attachment circuits have not been bound to VFI configured with the assigned VPN ID for each VLAN, this is a finding.'
  desc 'fix', 'Assign globally unique VPN IDs for each customer bridge domain using VPLS for carrier Ethernet services between multiple sites, and configure the attachment circuits to the appropriate VFI.

R1(config)#l2 vfi VPLS_A manual
R1(config-vfi)#vpn id 110
R1(config-vfi)#neighbor 10.3.3.3 encapsulation mpls
R1(config-vfi)#bridge-domain 100
R1(config-vfi)#exit
R1(config-if)#service instance 10 ethernet
R1(config-if-srv)#encapsulation untagged 
R1(config-if-srv)#bridge-domain 100
R1(config-if-srv)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17939r288063_chk'
  tag severity: 'high'
  tag gid: 'V-216706'
  tag rid: 'SV-216706r531086_rule'
  tag stig_id: 'CISC-RT-000680'
  tag gtitle: 'SRG-NET-000512-RTR-000009'
  tag fix_id: 'F-17937r288064_fix'
  tag 'documentable'
  tag legacy: ['V-96985', 'SV-106123']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
