control 'SV-221122' do
  title 'The Cisco PE switch providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE switches). A pseudowire contains two unidirectional label-switched paths (LSP) between two PE switches. Each MAC virtual forwarding table instance (VFI) is interconnected using pseudowires provisioned for the bridge domain, thereby maintaining privacy and logical separation between each VPLS bridge domain.

The VFI specifies the pseudowires associated with connecting PE switches and the customer-facing attachment circuits belonging to a given VLAN. Resembling a Layer 2 switch, the VFI is responsible for learning MAC addresses and providing loop-free forwarding of customer traffic to the appropriate end nodes. Each VPLS domain is identified by a globally unique VPN ID; hence, VFIs of the same VPLS domain must be configured with the same VPN ID on all participating PE switches. To guarantee traffic separation for all customer VLANs and that all packets are forwarded to the correct destination, it is imperative that the correct attachment circuits are associated with the appropriate VFI and that each VFI is associated to the unique VPN ID assigned to the customer VLAN.'
  desc 'check', 'Step 1: Review the implementation plan and the VPN IDs assigned to customer VLANs for the VPLS deployment.

Step 2: Review the PE switch configuration to verify that customer attachment circuits are associated to the appropriate VFI. In the example below, the attached circuit at interface GigabitEthernet3 is associated to VPN ID 110.

bridge-domain 100
 member vfi CUST1_VPLS
 member Ethernet2/2 service instance 1

l2vpn vfi context CUST1_VPLS
 vpn id 100
member Pseudowire12
member Pseudowire13
…
…
…
interface Ethernet2/2
 service instance 1 ethernet
 encapsulation dot1q 100
…
…
…
interface Pseudowire12 
 encapsulation mpls
 neighbor 10.2.2.2 100

interface Pseudowire13 
 encapsulation mpls
 neighbor 10.3.3.3 100

If the attachment circuits have not been bound to the VFI configured with the assigned VPN ID for each VLAN, this is a finding.'
  desc 'fix', 'Assign globally unique VPN IDs for each customer bridge domain using VPLS for carrier Ethernet services between multiple sites, and configure the attachment circuits to the appropriate VFI.

Step 1: Configure the pseudowire interfaces with the assigned VC-ID.

SW1(config)# interface Pseudowire12 
SW1(config-if-pseudowire)# neighbor 10.2.2.2 100
SW1(config-if-pseudowire)# encapsulation mpls
SW1(config-pseudowire-mpls)# exit
SW1(config-if-pseudowire)# exit
SW1(config)# interface Pseudowire13 
SW1(config-if-pseudowire)# neighbor 10.3.3.3 100
SW1(config-if-pseudowire)# encapsulation mpls
SW1(config-pseudowire-mpls)# exit
SW1(config-if-pseudowire)# exit

Step 2: Configure the virtual forwarding instance for the pseudowires as shown in the example with the assigned VPN ID.

SW1(config)# l2vpn vfi context CUST1_VPLS
SW1(config-l2vpn-vfi)# vpn 100
SW1(config-l2vpn-vfi)# member Pseudowire12
SW1(config-l2vpn-vfi)# member Pseudowire13
SW1(config-l2vpn-vfi)# exit

Step 3: Configure the service instance on the attachment circuit as shown in the example below:

SW1(config)# interface ethernet 2/2
SW1(config-if)# service instance 1 ethernet
SW1(config-if-srv)# encapsulation dot1q 100
SW1(config-if-srv)# exit
SW1(config-if)# exit

Step 4: Configure the bridge domain. 

SW1(config)# bridge-domain 100
SW1(config-bdomain)# member ethernet 2/2 service-instance 1
SW1(config-bdomain)# member vfi CUST1_VPLS
SW1(config-bdomain)# end

Note: The service instance configured on the attachment circuit must map to the service instance configured on the bridge domain in order to be bound to the correct bridge domain with the VFI that defines the appropriate VPN ID.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22837r409855_chk'
  tag severity: 'high'
  tag gid: 'V-221122'
  tag rid: 'SV-221122r622190_rule'
  tag stig_id: 'CISC-RT-000680'
  tag gtitle: 'SRG-NET-000512-RTR-000009'
  tag fix_id: 'F-22826r409856_fix'
  tag 'documentable'
  tag legacy: ['SV-111063', 'V-101959']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
