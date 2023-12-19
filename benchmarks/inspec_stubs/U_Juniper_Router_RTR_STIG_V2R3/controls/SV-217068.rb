control 'SV-217068' do
  title 'The Juniper PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).'
  desc 'The primary security model for an MPLS L3VPN as well as a VRF-lite infrastructure is traffic separation. Each interface can only be associated to one VRF, which is the fundamental framework for traffic separation. Forwarding decisions are made based on the routing table belonging to the VRF. Control of what routes are imported into or exported from a VRF is based on the RT. It is critical that traffic does not leak from one COI tenant or L3VPN to another; hence, it is imperative that the correct RT is configured for each VRF.'
  desc 'check', 'Review the design plan for MPLS/L3VPN and VRF-lite to determine what RTs have been assigned for each VRF.

Review the router configuration and verify that the correct RT is configured for each VRF. In the example below, route target 33:33 has been configured for customer 1.

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

If there are VRFs configured with the wrong RT, this is a finding.'
  desc 'fix', 'Configure the router to have each VRF instance defined with the correct RT.

[edit]
set routing-instances L3VPN_CUST1 vrf-target target:33:33'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18297r297072_chk'
  tag severity: 'high'
  tag gid: 'V-217068'
  tag rid: 'SV-217068r604135_rule'
  tag stig_id: 'JUNI-RT-000620'
  tag gtitle: 'SRG-NET-000512-RTR-000006'
  tag fix_id: 'F-18295r297073_fix'
  tag 'documentable'
  tag legacy: ['SV-101129', 'V-90919']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
