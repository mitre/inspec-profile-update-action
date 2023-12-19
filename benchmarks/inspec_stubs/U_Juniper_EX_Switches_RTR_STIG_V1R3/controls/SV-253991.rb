control 'SV-253991' do
  title 'The Juniper perimeter router must not be configured to redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the configuration of the router connecting to the alternate gateway and verify that redistribution of static routes to the alternate gateway is not occurring. Juniper routers use export policies to limit redistribution of routes. Verify a policy exists to filter route redistribution.

[edit policy-options]
policy-statement <name> {
    term 1 {
        from protocol static;
        then reject;
    }
}

Verify the export policy is applied to the EGP and/or IGP protocol.
[edit protocols]
bgp {
    export <policy-name>;
    group <group name> {
        type external;
        export <policy-name>;
        neighbor <address> {
            export <policy-name>;
        }
    }
    ospf {
        export <policy name>;
    }
    ospf3 {
        export <policy name>;
    }
}

Note: BGP supports export statements at the protocol level (global), the group level, and the neighbor level. Only the most specific policy is applied.

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering with a NIPRNet gateway or another autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router so that static routes are not redistributed to an alternate gateway into either an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other autonomous systems.
set policy-options policy-statement <policy name> term 1 from protocol static
set policy-options policy-statement <policy name> term 1 then reject

set protocols bgp group <group name> export <policy name>
set protocols bgp group <group name> neighbor <address> export <policy name>
set protocols bgp export <policy name>

set protocols ospf export <policy name>
set protocols ospf3 export <policy name>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57443r844004_chk'
  tag severity: 'low'
  tag gid: 'V-253991'
  tag rid: 'SV-253991r844006_rule'
  tag stig_id: 'JUEX-RT-000190'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-57394r844005_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
