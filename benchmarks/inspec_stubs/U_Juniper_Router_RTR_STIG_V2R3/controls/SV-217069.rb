control 'SV-217069' do
  title 'The Juniper PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).'
  desc 'An RD provides uniqueness to the customer address spaces within the MPLS L3VPN infrastructure. The concept of the VPN-IPv4 and VPN-IPv6 address families consists of the RD prepended before the IP address. Hence, if the same IP prefix is used in several different L3VPNs, it is possible for BGP to carry several completely different routes for that prefix, one for each VPN.

Since VPN-IPv4 addresses and IPv4 addresses are different address families, BGP never treats them as comparable addresses. The purpose of the RD is to create distinct routes for common IPv4 address prefixes. On any given PE router, a single RD can define a VRF in which the entire address space may be used independently, regardless of the makeup of other VPN address spaces. Hence, it is imperative that a unique RD is assigned to each L3VPN and that the proper RD is configured for each VRF.'
  desc 'check', 'Review the RDs that have been assigned for each VRF according to the plan provided by the ISSM. Review the router configuration and verify that the correct RD is configured for each VRF. In the example below, route distinguisher 33:33 has been configured for customer 1.

routing-instances {
    L3VPN_CUST1 {
        description "Between PE1 & PE2";
        instance-type vrf;
        interface ge-0/1/0.0;
        route-distinguisher 33:33;
        vrf-target target:33:33;
        vrf-table-label;
        protocols {
            ospf {
                area 0.0.0.1 {
                    interface ge-0/1/0.0;
                }
            }
        }
    }

If the wrong RD has been configured for any VRF, this is a finding.'
  desc 'fix', 'Configure the correct RD for each VRF.

[edit]
set routing-instances L3VPN_CUST1 route-distinguisher 33:33'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18298r297075_chk'
  tag severity: 'medium'
  tag gid: 'V-217069'
  tag rid: 'SV-217069r604135_rule'
  tag stig_id: 'JUNI-RT-000630'
  tag gtitle: 'SRG-NET-000512-RTR-000007'
  tag fix_id: 'F-18296r297076_fix'
  tag 'documentable'
  tag legacy: ['SV-101131', 'V-90921']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
