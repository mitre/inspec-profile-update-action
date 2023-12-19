control 'SV-254018' do
  title 'The Juniper out-of-band management (OOBM) gateway must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.'
  desc 'Using dedicated paths, the OOBM backbone connects the OOBM gateway routers located at the edge of the managed network and at the NOC. Dedicated links can be deployed using provisioned circuits or MPLS layer 2 and layer 3 VPN services or implementing a secured path with gateway-to-gateway IPsec tunnels. The tunnel mode ensures that the management traffic will be logically separated from any other traffic traversing the same path.'
  desc 'check', %q(This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC.

Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. MPLS-based VPN (L2 or L3) must have a working provider MPLS network including routing (for reachability) and Label Switched Paths (LSP). Additionally, the PE router will maintain separation for each CE router in individual routing instances. If using a dedicated circuit, verify the interface transporting NOC traffic is properly connected.

CE routers will not peer with PE routers when using L2 VPN. Verify the CE router peers with the appropriate CE router, generally with an IGP (e.g., OSPF), and not the PE router.
[edit interfaces]
<exterior interface> {
    unit <number> {
        family inet {
            address <IPv4 address>/<mask>;
        }
    }    
}
lo0 {
    unit 0 {
        family inet {
            address <IPv4 address>/32;
        }
    }
}
[edit protocols ospf]
area <number> {
    interface lo0.0;
    interface <exterior interface>.<number>;
}

CE routers will peer with PE routers, generally with eBGP, when using L3 VPN. Verify the CE router advertises the appropriate interior networks to the PE.
[edit interfaces]
<exterior interface>:0 {
    unit <number> {
        family inet {
            address <IPv4 address>/<mask>;
        }
    }
}
lo0 {
    family inet {
        address <IPv4 address>/<mask>;
    }
}
[edit routing-options]
router-id <ID>;
autonomous-system <AS #>;
[edit protocols bgp]
group PE1 {
    type external;
    export <policy name>;
    peer-as <peer AS #>;
    neighbor <neighbor address>; << Reachable from the exterior interface
}
[edit policy-options policy-statement <statement name>]
term 1 {
    from {
        protocol <protocol>; << Include the appropriate protocol (e.g., 'direct' for directly connected routes)
        route-filter <subnet>/<mask> <match condition>; << Include only interior routes that must be advertised to the L3 VPN
    }
    then accept;
}

Note: The policy-statement is applied as an export filter, using a route-filter to limit the exported routes. For example, assume 192.0.2.0/24 is the advertised route, and that it is directly connected. Using "protocol direct" will export all directly-connected routes, but no routes learned via an IGP (e.g., OSPF). Using "route-filter 192.0.2.0/24 orlonger then accept" will accept that /24 (or longer mask) and deny all others. Verify the match condition is appropriate for the desired advertisement.

If management traffic is not transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel, this is a finding.)
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

CE peering to CE (L2 VPN):
set interfaces <exterior interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces lo0 unit 0 family inet address <IPv4 address>/32
set protocols ospf area <number> interface lo0.0
set protocols ospf area <number> interface <exterior interface>

CE peering to PE (L3 VPN):
set system host-name ce1
set interfaces <exterior interface>:<number> description "Link from CE1 to PE1 for L3vpn"
set interfaces <exterior interface>:<number> unit <number> family inet address <IPv4 address>/<mask>
set interfaces lo0 unit 0 family inet address <IPv4 address>/32
set routing-options router-id <ID>
set routing-options autonomous-system <AS #>
set protocols bgp group <name> type external
set protocols bgp group <name> export <policy name>
set protocols bgp group <name> peer-as <Peer AS #>
set protocols bgp group <name> neighbor <neighbor address>
set policy-options policy-statement <policy name> term 1 from protocol <protocol>
set policy-options policy-statement <policy name> term 1 from route-filter <subnet> <match criterion>
set policy-options policy-statement <policy name> term 1 then accept

Ensure that a dedicated circuit, MPLS/VPN service, or IPsec tunnel is deployed to transport management traffic between the managed network and the NOC.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57470r844085_chk'
  tag severity: 'medium'
  tag gid: 'V-254018'
  tag rid: 'SV-254018r844087_rule'
  tag stig_id: 'JUEX-RT-000460'
  tag gtitle: 'SRG-NET-000205-RTR-000009'
  tag fix_id: 'F-57421r844086_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
