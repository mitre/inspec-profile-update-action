control 'SV-217046' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify that the OOBM interface is an adjacency in the IGP domain for the management network via separate VRF as shown in the example below.

}
protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-2/0/0;
            interface ge-2/1/0;
        }
    }
}
routing-instances {
    VRF_MGMT {
        instance-type vrf;
        interface ge-1/0/0;
        interface ge-1/1/0;
        route-distinguisher 10.1.12.0:12;
        vrf-target {
            import target:1234:4567;
            export target:1234:4567;
        }
        routing-options {
            router-id 11.11.11.11;
        }
        protocols {
            ospf {
                area 0.0.0.0 {
                    interface ge-1/0/0;
                    interface ge-1/1/0;
                }
            }
        }
    }
}

If the router is not configured to have separate IGP instances for the managed network and management network, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to have a separate IGP instance for the management network as shown in the example below.

[edit routing-instances]
set VRF_MGMT instance-type vrf
set VRF_MGMT route-distinguisher 10.1.12.0:12
set VRF_MGMT vrf-target import target:1234:4567
set VRF_MGMT vrf-target export target:1234:4567
set VRF_MGMT interface ge-1/0/0
set VRF_MGMT interface ge-1/1/0
set VRF_MGMT protocols ospf area 0.0.0.0 interface ge-1/0/0
set VRF_MGMT protocols ospf area 0.0.0.0 interface ge-1/1/0
set VRF_MGMT routing-options router-id 11.11.11.11'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18275r297006_chk'
  tag severity: 'medium'
  tag gid: 'V-217046'
  tag rid: 'SV-217046r604135_rule'
  tag stig_id: 'JUNI-RT-000410'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-18273r297007_fix'
  tag 'documentable'
  tag legacy: ['SV-101087', 'V-90877']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
