control 'SV-254066' do
  title 'The Juniper PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).'
  desc 'An RD provides uniqueness to the customer address spaces within the MPLS L3VPN infrastructure. The concept of the VPN-IPv4 and VPN-IPv6 address families consists of the RD prepended before the IP address. Hence, if the same IP prefix is used in several different L3VPNs, it is possible for BGP to carry several completely different routes for that prefix, one for each VPN.

Since VPN-IPv4 addresses and IPv4 addresses are different address families, BGP never treats them as comparable addresses. The purpose of the RD is to create distinct routes for common IPv4 address prefixes. On any given PE router, a single RD can define a VRF in which the entire address space may be used independently, regardless of the makeup of other VPN address spaces. Hence, it is imperative that a unique RD is assigned to each L3VPN and that the proper RD is configured for each VRF.'
  desc 'check', 'Review the RDs that have been assigned for each VRF according to the plan provided by the ISSM.

Review all VRFs configured on CE-facing interfaces and verify that the proper RD has been configured for each. Assuming the assigned RD for "customer 1" is "33:33", verify the route-distinguisher matches.

[edit routing-instances]
<instance name> {
    description "To customer 1";
    instance-type vrf;
    interface <ce-facing interface>.<logical unit>;
    route-distinguisher 33:33; << Must match the design plan for "customer 1".
    vrf-target cust1:33:33; << Must match the design plan for "customer 1".
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

If the wrong RD has been configured for any VRF, this is a finding.'
  desc 'fix', 'Configure the correct RD for each VRF.

set routing-instances <name> description <"appropriate description">
set routing-instances <name> instance-type vrf
set routing-instances <name> interface <ce-facing interface>.<logical unit>
set routing-instances <name> route-distinguisher 33:33 << Must match the design plan for "customer 1".
set routing-instances <name> vrf-target cust1:33:33 << Must match the design plan for "customer 1".
set routing-instances <name> vrf-table-label
set routing-instances <name> protocols ospf area <number> interface <ce-facing interface>.<logical unit>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57518r844229_chk'
  tag severity: 'medium'
  tag gid: 'V-254066'
  tag rid: 'SV-254066r844231_rule'
  tag stig_id: 'JUEX-RT-000940'
  tag gtitle: 'SRG-NET-000512-RTR-000007'
  tag fix_id: 'F-57469r844230_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
