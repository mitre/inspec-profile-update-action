control 'SV-217035' do
  title 'The Juniper perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the configurations under the protocols hierarchy. If the export statement is configured as shown in the example below proceed to step 2.

}
protocols {
    bgp {
        group AS_5 {
            type external;
            export REDISTRIBUTE;
            peer-as 5;
        …
        …
        …
            }
        }
    }
    ospf {
        export REDISTRIBUTE;
        area 0.0.0.0 {
            interface ge-0/0/0 {
            …
            …
            …
            }
        }
    }
}

Review the export policy referenced above to determine if static routes are being exported as shown in the example below.

policy-options {
    …
    …
    …
    }
    policy-statement REDISTRIBUTE {
        term EXPORT_STATIC {
            from protocol static;
            then accept;
        }
    }
}

Review the static routes that have been configured to determine if there routes with the next hop address that of the alternate gateway.

routing-options {
    static {
        route 10.1.16.0/24 next-hop 10.1.12.1;
        route 0.0.0.0/0 next-hop 144.22.1.3;
    }

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering to a NIPRNet gateway or any other autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router so that static routes are not redistributed to an alternate gateway into either a BGP or any IGP peering with the NIPRNet or to any other autonomous systems. This can be done by excluding that route in the export policy as shown in the example below.

[edit policy-options policy-statement REDISTRIBUTE]
set term NOT_ISP_DEFAULT from protocol static route-filter 0.0.0.0/0 exact
set term NOT_ISP_DEFAULT then reject
insert term set term NOT_ISP_DEFAULT before term EXPORT_STATIC'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18264r296973_chk'
  tag severity: 'low'
  tag gid: 'V-217035'
  tag rid: 'SV-217035r604135_rule'
  tag stig_id: 'JUNI-RT-000300'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-18262r296974_fix'
  tag 'documentable'
  tag legacy: ['SV-101065', 'V-90855']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
