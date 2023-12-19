control 'SV-254064' do
  title 'The Juniper PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', %q(Review the design plan for deploying L3VPN and VRF-lite. 

Review all CE-facing interfaces and verify that the proper VRF is defined.
[edit interfaces]
<ce-facing interface> {
    description "To customer 1";
    unit <number> {
        family inet {
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            address <IPv6 address>/<prefix>;
        }
    }
}

[edit routing-instances]
<instance name> {
    description "To customer 1";
    instance-type vrf;
    interface <ce-facing interface>.<logical unit>;
    route-distinguisher <Number in (16 bit:32 bit) or (32 bit 'L':16 bit) or (IP address:16 bit) format>;
    vrf-target <Target community to use in import and export>;
    vrf-table-label;
    protocols {
        ospf {
            area <number> {
                interface <ce-facing interface>.<logical unit>;
            }
        }
    }
}

Note: In L3 VPN, the CE router forms an adjacency with the PE router (OSPF in the example).

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.)
  desc 'fix', %q(Configure the PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.

set interfaces <ce facing interface> description <"appropriate description">
set interfaces <ce facing interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <ce facing interface> unit <number> family inet6 address <IPv6 address>/<prefix>

set routing-instances <name> description <"appropriate description">
set routing-instances <name> instance-type vrf
set routing-instances <name> interface <ce-facing interface>.<logical unit>
set routing-instances <name> route-distinguisher <Number in (16 bit:32 bit) or (32 bit 'L':16 bit) or (IP address:16 bit) format>
set routing-instances <name> vrf-target <Target community to use in import and export>
set routing-instances <name> vrf-table-label
set routing-instances <name> protocols ospf area <number> interface <ce-facing interface>.<logical unit>)
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57516r844223_chk'
  tag severity: 'high'
  tag gid: 'V-254064'
  tag rid: 'SV-254064r844225_rule'
  tag stig_id: 'JUEX-RT-000920'
  tag gtitle: 'SRG-NET-000512-RTR-000005'
  tag fix_id: 'F-57467r844224_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
