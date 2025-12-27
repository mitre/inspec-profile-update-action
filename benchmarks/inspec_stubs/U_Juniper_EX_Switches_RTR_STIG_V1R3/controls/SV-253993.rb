control 'SV-253993' do
  title 'The Juniper out-of-band management (OOBM) gateway router must not be configured to redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify the Interior Gateway Protocol instance used for the managed network does not redistribute routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

Juniper routers use export policies to limit redistribution of routes. Verify a policy exists to filter route redistribution. Juniper policy-statements support terms, which provides greater granularity within a single policy. 

[edit policy-options]
policy-statement deny-mgt-redist {
    term 1 {
        from protocol static;
        then reject;
    }
    term 2 { 
        from {
            protocol ospf;
            route-filter <IPv4 subnet>/<mask> orlonger;
            route-filter <IPv6 subnet>/<prefix> orlonger;
        }
        then reject;
    }
    <additional terms permitting authorized routes for redistribution>
}
policy-statement deny-managed-routes {
    term 1 {
        from {
            route-filter <IPv4 subnet>/<mask> orlonger;
            route-filter <IPv6 subnet>/<prefix> orlonger;
        }
        then accept;
    }
    term 2 {
        then reject;
    }
}

Verify an export policy is applied to the IGP protocol for each routing instance (default and OOBM).
[edit protocols]
    ospf {
        area <area number> {
            interface <NOT OOBM interface>.<logical unit>;
        }
        export deny-mgt-redist;
    }
    ospf3 {
        area <area number> {
            interface <NOT OOBM interface>.<logical unit>;
        }
        export deny-mgt-redist;
    }
}
[edit routing-instances]
OOBM {
    instance-type virtual-router;
    protocols {
        ospf {
            area <area number> {
                interface <OOBM interface>.<logical unit>;
            }
            export deny-managed-routes;
        }
        ospf3 {
            area <area number> {
                interface <OOBM interface>.<logical unit>;
            }
            export deny-managed-routes;
        }
    }
}

If the Interior Gateway Protocol instance used for the managed network redistributes routes into the Interior Gateway Protocol instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the Interior Gateway Protocol instance used for the managed network to prohibit redistribution of routes into the Interior Gateway Protocol instance used for the management network, and vice versa.

set policy-options policy-statement deny-managed-routes term 1 from route-filter <IPv4 subnet>/<mask> orlonger
set policy-options policy-statement deny-managed-routes term 1 from route-filter <IPv6 subnet>/<prefix> orlonger
set policy-options policy-statement deny-managed-routes term 1 then accept
set policy-options policy-statement deny-managed-routes term 2 then reject
set policy-options policy-statement deny-mgt-redist term 1 from protocol static
set policy-options policy-statement deny-mgt-redist term 1 then reject
set policy-options policy-statement deny-mgt-redist term 2 from protocol ospf
set policy-options policy-statement deny-mgt-redist term 2 from route-filter <IPv4 subnet>/<mask> orlonger
set policy-options policy-statement deny-mgt-redist term 2 from route-filter <IPv6 subnet>/<prefix> orlonger
set policy-options policy-statement deny-mgt-redist term 2 then reject
<additional terms for permitted redistributable routes>

set routing-instances OOBM instance-type virtual-router
set routing-instances OOBM protocols ospf area <area number> interface <OOBM interface>.<logical unit>
set routing-instances OOBM protocols ospf export test
set routing-instances OOBM protocols ospf3 area <area number> interface <OOBM interface>.<logical unit>
set routing-instances OOBM protocols ospf3 export test'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57445r844010_chk'
  tag severity: 'medium'
  tag gid: 'V-253993'
  tag rid: 'SV-253993r844012_rule'
  tag stig_id: 'JUEX-RT-000210'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-57396r844011_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
