control 'SV-217075' do
  title 'The Juniper PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP). Each MAC forwarding table instance is interconnected using domain-specific LSPs, thereby maintaining privacy and logical separation between each VPLS domain.

When a frame arrives on a bridge port (pseudowire or attachment circuit) and the source MAC address is unknown to the receiving PE router, the source MAC address is associated with the pseudowire or attachment circuit and the forwarding table is updated accordingly. Frames are forwarded to the appropriate pseudowire or attachment circuit according to the forwarding table entry for the destination MAC address. Ethernet frames sent to broadcast and unknown destination addresses must be flooded out to all interfaces for the bridge domain; hence, a PE router must replicate packets across both attachment circuits and pseudowires.

A malicious attacker residing in a customer network could launch a source MAC address spoofing attack by flooding packets to a valid unicast destination, each with a different MAC source address. The PE router receiving this traffic would try to learn every new MAC address and would quickly run out of space for the VFI forwarding table. Older, valid MAC addresses would be removed from the table, and traffic sent to them would have to be flooded until the storm threshold limit is reached. Hence, it is essential that a limit is established to control the number of MAC addresses that will be learned and recorded into the forwarding table for each bridge domain.'
  desc 'check', 'Review the PE router configuration to determine if a MAC address limit has been set for each VPLS bridge domain.

routing-instances {
    VPLS_CUST2 {
        instance-type vpls;
        interface ge-0/1/0.0; 
        route-distinguisher 22:22;
        vrf-target target:22:22;
        protocols {
            vpls {
                site-range 9;
                mac-table-size {
                   nnnn;
                }
                no-tunnel-services;
                site R8 {
                    site-identifier 8;
                    interface ge-0/1/0.0;
                }
                vpls-id 102;
                neighbor 8.8.8.8;
            }
        }
    }
}

If a limit has not been configured, this is a finding.'
  desc 'fix', 'Configure a MAC address learning limit for each VPLS bridge domain.

[edit routing-instances VPLS_CUST2 protocols vpls]
set mac-table-size nnnn'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18304r297093_chk'
  tag severity: 'medium'
  tag gid: 'V-217075'
  tag rid: 'SV-217075r639663_rule'
  tag stig_id: 'JUNI-RT-000700'
  tag gtitle: 'SRG-NET-000192-RTR-000002'
  tag fix_id: 'F-18302r297094_fix'
  tag 'documentable'
  tag legacy: ['V-90931', 'SV-101141']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
