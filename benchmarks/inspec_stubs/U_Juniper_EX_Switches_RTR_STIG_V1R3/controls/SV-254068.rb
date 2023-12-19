control 'SV-254068' do
  title 'The Juniper PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP) between two PE routers. Each MAC virtual forwarding table instance (VFI) is interconnected using pseudowires provisioned for the bridge domain, thereby maintaining privacy and logical separation between each VPLS bridge domain.

The VFI specifies the pseudowires associated with connecting PE routers and the customer-facing attachment circuits belonging to a given VLAN. Resembling a layer 2 switch, the VFI is responsible for learning MAC addresses and providing loop-free forwarding of customer traffic to the appropriate end nodes. Each VPLS domain is identified by a globally unique VPN ID; hence, VFIs of the same VPLS domain must be configured with the same VPN ID on all participating PE routers. To guarantee traffic separation for all customer VLANs and that all packets are forwarded to the correct destination, it is imperative that the correct attachment circuits are associated with the appropriate VFI and that each VFI is associated to the unique VPN ID assigned to the customer VLAN.'
  desc 'check', 'Review the implementation plan and the VPN IDs assigned to customer VLANs for the VPLS deployment.

Review the PE router configuration to verify that customer attachment circuits (i.e., VLANs) are associated to the appropriate VPLS ID.

Review the implementation plan and the VPLS IDs assigned to customer VLANs for the VPLS deployment.

Review the PE router configuration to verify that customer attachment circuits are associated to the appropriate routing instance configured for the customers VPLS ID.

[edit]
routing-instances {
    <instance name> {
        interface <interface name>.<logical unit>;
        protocols {
            vpls {
                vpls-id <VPLS ID>;
                    neighbor <neighbor address>;
                }
            }
        }
    }
}

Note: Only EX9200-series devices currently support VPLS.

If the attachment circuits have not been bound to the appropriate routing-instance with the assigned VPN ID for each associated VLAN, this is a finding.'
  desc 'fix', 'Assign globally unique VPN IDs for each customer VLAN using VPLS for carrier Ethernet services between multiple sites, and configure the attachment circuits to the appropriate VFI.

set routing-instances <instance name> protocols vpls vpls-id <VPLS ID> neighbor <neighbor address>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57520r844235_chk'
  tag severity: 'high'
  tag gid: 'V-254068'
  tag rid: 'SV-254068r844237_rule'
  tag stig_id: 'JUEX-RT-000960'
  tag gtitle: 'SRG-NET-000512-RTR-000009'
  tag fix_id: 'F-57471r844236_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
