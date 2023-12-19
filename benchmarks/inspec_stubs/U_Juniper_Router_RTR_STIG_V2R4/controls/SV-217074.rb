control 'SV-217074' do
  title 'The Juniper PE router must be configured to implement Protocol Independent Multicast (PIM) snooping  for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'PIM snooping provides a way to constrain multicast traffic at Layer 2. By monitoring PIM join and prune packets on each interface, the PE router is able to determine interested multicast receivers and hence will populate the layer 2 multicast-forwarding table. This enables the PE router to deliver traffic only to ports with at least one interested member within the VPLS bridge, thereby significantly reducing the volume of multicast traffic that would otherwise flood an entire VPLS bridge domain. The PIM snooping operation applies to both access circuits and pseudowires within a VPLS bridge domain.'
  desc 'check', 'Review the router configuration to verify that PIM snooping has been configured under the routing instance protocols hierarchy for each VPLS bridge domain as shown in the example.

routing-instances {
    VPLS_CUST2 {
        instance-type vpls;
        interface ge-0/1/0.0;  
        route-distinguisher 22:22;
        vrf-target target:22:22;
        }
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
            pim-snooping;
            }
        }
    }
}

If the router is not configured to implement PIM  snooping for each VPLS bridge domain, this is a finding.'
  desc 'fix', 'Configure PIM snooping for each VPLS bridge domain as shown in the example below.

[edit routing-instances VPLS_CUST2]
set routing-instances VPLS_CUST2 protocols pim-snooping'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18303r297090_chk'
  tag severity: 'low'
  tag gid: 'V-217074'
  tag rid: 'SV-217074r604135_rule'
  tag stig_id: 'JUNI-RT-000690'
  tag gtitle: 'SRG-NET-000362-RTR-000119'
  tag fix_id: 'F-18301r297091_fix'
  tag 'documentable'
  tag legacy: ['SV-101139', 'V-90929']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
