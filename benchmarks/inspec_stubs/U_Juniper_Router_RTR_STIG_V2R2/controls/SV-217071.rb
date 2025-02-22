control 'SV-217071' do
  title 'The Juniper PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.'
  desc 'VPWS is an L2VPN technology that provides a virtual circuit between two PE routers to forward Layer 2 frames between two customer-edge routers or switches through an MPLS-enabled IP core. The ingress PE router (virtual circuit head-end) encapsulates Ethernet frames inside MPLS packets using label stacking and forwards them across the MPLS network to the egress PE router (virtual circuit tail-end). During a virtual circuit setup, the J-PE routers exchange VC label bindings for the specified VC ID. The VC ID specifies a pseudowire associated with an ingress and egress PE router and the customer-facing attachment circuits. 

To guarantee that all frames are forwarded onto the correct pseudowire and to the correct customer and attachment circuits, it is imperative that the correct VC ID is configured for each attachment circuit.'
  desc 'check', 'Review the ingress and egress PE router configuration for each virtual circuit that has been provisioned.

Verify that the correct and unique VCID has been configured for the appropriate attachment circuit. In the example below ge-0/1/0 is the CE-facing interface that is configured for VPWS (aka pseudowire).

interfaces {
    ge-0/1/0.0 {
        encapsulation ethernet-ccc;
        unit 0 {
        }
    }
…
…
…
protocols {
    …
    …
    …
    }
    l2circuit {
        neighbor 8.8.8.8 {
            interface ge-0/1/0.0{
                virtual-circuit-id 13;
            }
        }
    }

If the correct VC ID has not been configured on both routers, this is a finding.

Note: Ethernet over MPLS in VLAN mode transports Ethernet traffic from a source 802.1Q VLAN to a destination 802.1Q VLAN over a core MPLS network. The VC ID must be unique and the same on each end as it is used to connect the endpoints of the VC.'
  desc 'fix', 'Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID. Configure the same VC ID on both ends of the VC.

[edit protocols l2circuit]
set neighbor 8.8.8.8 interface em0 virtual-circuit-id 13'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18300r297081_chk'
  tag severity: 'high'
  tag gid: 'V-217071'
  tag rid: 'SV-217071r639663_rule'
  tag stig_id: 'JUNI-RT-000650'
  tag gtitle: 'SRG-NET-000512-RTR-000008'
  tag fix_id: 'F-18298r297082_fix'
  tag 'documentable'
  tag legacy: ['SV-101191', 'V-90981']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
