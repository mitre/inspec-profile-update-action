control 'SV-217067' do
  title 'The Juniper PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', 'Review the design plan for deploying L3VPN and VRF-lite. 

Review all CE-facing interfaces and verify that the proper VRF is defined. The example below depicts the CE-facing interface ge-0/1/0 bound to VRF titled L3VPN_CUST1. Notice that the PE router is peering OSPF with the CE router.

interfaces {
    …
    …
    …
    }
    ge-0/1/0 {
        description "link to Customer 1";
        unit 0 {
            family inet {
                address 101.3.44.6/30;
            }
        }
    }
    …
    …
    …
}

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
}

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.'
  desc 'fix', 'Configure the PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs as shown in the example below.

[edit]
set routing-instances L3VPN_CUST1 instance-type vrf
set routing-instances L3VPN_CUST1 description "Between PE1 & PE2"
set routing-instances L3VPN_CUST1 interface ge-0/1/0.0
set routing-instances L3VPN_CUST1 protocols ospf interface area 1 ge-0/1/0.0
set routing-instances L3VPN_CUST1 route-distinguisher 33:33
set routing-instances L3VPN_CUST1 vrf-target target:33:33 
set routing-instances L3VPN_CUST1 vrf-table-label'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18296r297069_chk'
  tag severity: 'high'
  tag gid: 'V-217067'
  tag rid: 'SV-217067r604135_rule'
  tag stig_id: 'JUNI-RT-000610'
  tag gtitle: 'SRG-NET-000512-RTR-000005'
  tag fix_id: 'F-18294r297070_fix'
  tag 'documentable'
  tag legacy: ['SV-101127', 'V-90917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
