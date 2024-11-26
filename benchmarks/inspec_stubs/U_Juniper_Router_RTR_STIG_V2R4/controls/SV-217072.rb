control 'SV-217072' do
  title 'The Juniper PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the routing instance with the globally unique VPLS ID assigned for each customer VLAN.'
  desc 'VPLS defines an architecture that delivers Ethernet multipoint services over an MPLS network. Customer Layer 2 frames are forwarded across the MPLS core via pseudowires using IEEE 802.1q Ethernet bridging principles. A pseudowire is a virtual bidirectional connection between two attachment circuits (virtual connections between PE and CE routers). A pseudowire contains two unidirectional label-switched paths (LSP) between two PE routers. Each MAC virtual forwarding table instance is interconnected using pseudowires provisioned for the bridge domain, thereby maintaining privacy and logical separation between each VPLS bridge domain.

The forwarding table instance specifies the pseudowires associated with connecting PE routers and the customer-facing attachment circuits belonging to a given VLAN. Resembling a Layer 2 switch, the forwarding table instance is responsible for learning MAC addresses and providing loop-free forwarding of customer traffic to the appropriate end nodes. Each VPLS domain is identified by a globally unique VPN ID; hence, VFIs of the same VPLS domain must be configured with the same VPLS ID on all participating PE routers. To guarantee traffic separation for all customer VLANs and that all packets are forwarded to the correct destination, it is imperative that the correct attachment circuits are associated with the appropriate forwarding table instance and that each forwarding table instance is associated to the unique VPLS ID assigned to the customer VLAN.'
  desc 'check', 'Review the implementation plan and the VPLS IDs assigned to customer VLANs for the VPLS deployment.

Review the PE router configuration to verify that customer attachment circuits are associated to the appropriate routing instance configured for the customers VPLS ID.

interfaces {
    ge-0/1/0.0 {
        encapsulation ethernet-vpls;
        unit 0 {
        }
    }
…
…
…
routing-instances {
    VPLS_CUST2 {
        instance-type vpls;
        interface ge-0/1/0.0;
        route-distinguisher 22:22;
        vrf-target target:22:22;
        protocols {
            vpls {
                site-range 9;
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

If the attachment circuits have not been bound to appropriate routing instance configured with the assigned VPLS ID for each customer VLAN, this is a finding.'
  desc 'fix', 'Assign globally unique VPLS ID to each VPLS routing instance as shown in the example.

[edit routing-instances VPLS_CUST2 protocols vpls]
set vpls-id 102 neighbor 8.8.8.8'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18301r297084_chk'
  tag severity: 'high'
  tag gid: 'V-217072'
  tag rid: 'SV-217072r604135_rule'
  tag stig_id: 'JUNI-RT-000660'
  tag gtitle: 'SRG-NET-000512-RTR-000009'
  tag fix_id: 'F-18299r297085_fix'
  tag 'documentable'
  tag legacy: ['SV-101135', 'V-90925']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
