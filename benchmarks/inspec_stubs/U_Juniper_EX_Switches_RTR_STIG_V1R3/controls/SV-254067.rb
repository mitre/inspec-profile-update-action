control 'SV-254067' do
  title 'The Juniper PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.'
  desc 'VPWS is an L2VPN technology that provides a virtual circuit between two PE routers to forward layer 2 frames between two customer-edge routers or switches through an MPLS-enabled IP core. The ingress PE router (virtual circuit head-end) encapsulates Ethernet frames inside MPLS packets using label stacking and forwards them across the MPLS network to the egress PE router (virtual circuit tail-end). During a virtual circuit setup, the PE routers exchange VC label bindings for the specified VC ID. The VC ID specifies a pseudowire associated with an ingress and egress PE router and the customer-facing attachment circuits.

To guarantee that all frames are forwarded onto the correct pseudowire and to the correct customer and attachment circuits, it is imperative that the correct VC ID is configured for each attachment circuit.'
  desc 'check', 'Review the ingress and egress PE router configuration for each virtual circuit that has been provisioned.

Verify that the correct and unique VCID has been configured for the appropriate attachment circuit.

[edit interfaces]
<interface name> {
    encapsulation ethernet-ccc;
    unit <number> {
        <additional configuration>
    }
}

[edit protocols]
l2circuit {
    neighbor 1.1.1.1 {
        interface <interface name>.<logical unit> {
            virtual-circuit-id <1..4294967295>;
        }
    }
}

If the correct VC ID has not been configured on both routers, this is a finding.

Note: Ethernet over MPLS in VLAN mode transports Ethernet traffic from a source 802.1Q VLAN to a destination 802.1Q VLAN over a core MPLS network. The VC ID must be unique and the same on each end as it is used to connect the endpoints of the VC.'
  desc 'fix', 'Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID.

Configure the same VC ID on both ends of the VC.

set interfaces <interface name> unit <number> encapsulation vlan-ccc
set protocols l2circuit neighbor <neighbor> interface <interface>.<logical unit> virtual-circuit-id <1..4294967295>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57519r844232_chk'
  tag severity: 'high'
  tag gid: 'V-254067'
  tag rid: 'SV-254067r844234_rule'
  tag stig_id: 'JUEX-RT-000950'
  tag gtitle: 'SRG-NET-000512-RTR-000008'
  tag fix_id: 'F-57470r844233_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
