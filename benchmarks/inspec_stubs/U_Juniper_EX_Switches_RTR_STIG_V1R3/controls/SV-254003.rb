control 'SV-254003' do
  title 'The Juniper PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP). Each MAC forwarding table instance is interconnected using domain-specific LSPs, thereby maintaining privacy and logical separation between each VPLS domain.

When a frame arrives on a bridge port (pseudowire or attachment circuit) and the source MAC address is unknown to the receiving PE router, the source MAC address is associated with the pseudowire or attachment circuit and the forwarding table is updated accordingly. Frames are forwarded to the appropriate pseudowire or attachment circuit according to the forwarding table entry for the destination MAC address. Ethernet frames sent to broadcast and unknown destination addresses must be flooded out to all interfaces for the bridge domain; hence, a PE router must replicate packets across both attachment circuits and pseudowires.

A malicious attacker residing in a customer network could launch a source MAC address spoofing attack by flooding packets to a valid unicast destination, each with a different MAC source address. The PE router receiving this traffic would try to learn every new MAC address and would quickly run out of space for the VFI forwarding table. Older, valid MAC addresses would be removed from the table, and traffic sent to them would have to be flooded until the storm threshold limit is reached. Hence, it is essential that a limit is established to control the number of MAC addresses that will be learned and recorded into the forwarding table for each bridge domain.'
  desc 'check', 'Review the PE router configuration to determine if a MAC address limit has been set for each bridge domain.

Verify the MAC address limit is globally defined for the VPLS protocol or at each interface assigned to the routing instance.

[edit routing-instance]
<instance name> {
    protocols {
        vpls {
            interface-mac-limit {
                <value>;
            }
            interface <interface name>.<logical unit> {
                interface-mac-limit {
                    <value>;
                }
            }
        }
    }
}

Note: Only EX9200-series devices currently support VPLS.

If a limit has not been configured, this is a finding.'
  desc 'fix', 'Configure a MAC address learning limit for each VPLS bridge domain.

set routing-instance <name> protocols vpls interface-mac-limit <value>
set routing-instance <name> protocols vpls interface <name>.<logical unit> interface-mac-limit <value>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57455r844040_chk'
  tag severity: 'medium'
  tag gid: 'V-254003'
  tag rid: 'SV-254003r844042_rule'
  tag stig_id: 'JUEX-RT-000310'
  tag gtitle: 'SRG-NET-000192-RTR-000002'
  tag fix_id: 'F-57406r844041_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
