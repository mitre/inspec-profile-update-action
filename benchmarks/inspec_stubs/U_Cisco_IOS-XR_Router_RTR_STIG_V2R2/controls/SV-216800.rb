control 'SV-216800' do
  title 'The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP). Each MAC forwarding table instance is interconnected using domain-specific LSPs, thereby maintaining privacy and logical separation between each VPLS domain.

When a frame arrives on a bridge port (pseudowire or attachment circuit) and the source MAC address is unknown to the receiving PE router, the source MAC address is associated with the pseudowire or attachment circuit and the forwarding table is updated accordingly. Frames are forwarded to the appropriate pseudowire or attachment circuit according to the forwarding table entry for the destination MAC address. Ethernet frames sent to broadcast and unknown destination addresses must be flooded out to all interfaces for the bridge domain; hence, a PE router must replicate packets across both attachment circuits and pseudowires.

A malicious attacker residing in a customer network could launch a source MAC address spoofing attack by flooding packets to a valid unicast destination, each with a different MAC source address. The PE router receiving this traffic would try to learn every new MAC address and would quickly run out of space for the VFI forwarding table. Older, valid MAC addresses would be removed from the table, and traffic sent to them would have to be flooded until the storm threshold limit is reached. Hence, it is essential that a limit is established to control the number of MAC addresses that will be learned and recorded into the forwarding table for each bridge domain.'
  desc 'check', 'Review the PE router configuration to determine if a MAC address limit has been set for each VPLS bridge domain.

bridge group L2GROUP
  bridge-domain L2_BRIDGE_COI1
   interface GigabitEthernet0/0/0/2
    mac
     limit
      maximum nnnn
     !
    !

If a limit has not been configured, this is a finding.'
  desc 'fix', 'Configure a MAC address learning limit for each VPLS bridge domain.

RP/0/0/CPU0:R3(config)#l2vpn
RP/0/0/CPU0:R3(config-l2vpn)#bridge group L2GROUP
RP/0/0/CPU0:R3(config-l2vpn-bg)#bridge-domain L2_BRIDGE_COI1
RP/0/0/CPU0:R3(config-l2vpn-bg-bd)#interface GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#mac limit maximum nnn
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18032r288777_chk'
  tag severity: 'medium'
  tag gid: 'V-216800'
  tag rid: 'SV-216800r531087_rule'
  tag stig_id: 'CISC-RT-000720'
  tag gtitle: 'SRG-NET-000192-RTR-000002'
  tag fix_id: 'F-18030r288778_fix'
  tag 'documentable'
  tag legacy: ['SV-105945', 'V-96807']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
