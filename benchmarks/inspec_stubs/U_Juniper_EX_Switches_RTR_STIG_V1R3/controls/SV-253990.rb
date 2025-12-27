control 'SV-253990' do
  title 'The Juniper perimeter router must not be configured to be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e., other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRNet routes could be advertised to the ISP; thereby creating a backdoor connection from the internet to the NIPRNet.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the configuration of the router connecting to the alternate gateway.

Review the [edit protocols bgp] hierarchy and verify there are no BGP neighbors configured to the remote AS that belongs to the alternate gateway service provider. For example:
[edit protocols bgp]
group eBGP {
    type external;
    peer-as 2;
    neighbor <address-1> {
        <bgp neighbor configuration>;
    }
    neighbor <address-2> {
        <bgp neighbor configuration>;
    }
}

Note: Neither neighbor can belong to a peer AS belonging to the alternate gateway service provider.

Verify static routing to the peer AS belonging to the alternate gateway service provider. For example:
[edit routing-options]
rib inet6.0 {
    static {
        route <peer AS IPv6 subnet>/<prefix> next-hop <peer AS router>;
    }
}
static {
    route <peer AS IPv4 subnet>/<mask> next-hop <peer AS router>;
}

If there are BGP neighbors connecting the remote AS of the alternate gateway service provider, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Remove BGP neighbors belonging to the alternate gateway service provider.

delete protocols bgp group <name> neighbor <peer AS belonging to alternate gateway service provider>

Configure a static route on the perimeter router to reach the AS of a router connecting to an alternate gateway.

set routing-options rib inet6.0 static route <IPv6 subnet>/<prefix> next-hop <peer AS router>
set routing-options static route <IPv4 subnet>/<mask> next-hop <peer AS router>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57442r844001_chk'
  tag severity: 'high'
  tag gid: 'V-253990'
  tag rid: 'SV-253990r844003_rule'
  tag stig_id: 'JUEX-RT-000180'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-57393r844002_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
