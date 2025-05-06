control 'SV-254014' do
  title 'The Juniper perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.'
  desc 'Firewall filters are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of firewall filters for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', %q(This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that the egress firewall filter is bound to the internal interface in an inbound direction. 

[edit interfaces]
<internal interface> {
    unit <number> {
        family inet {
            filter {
                input outbound-ipv4;
            }
        }
        family inet6 {
            filter {
                input outbound-ipv6;
            }
        }
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output' change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured to filter traffic leaving the network at the internal interface in an inbound direction, this is a finding.)
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure an egress firewall filter bound to the internal interface in an inbound direction to filter traffic leaving the network.

set interfaces <internal interface name> unit <number> family inet filter input outbound-ipv4
set interfaces <internal interface name> unit <number> family inet6 filter input outbound-ipv6'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57466r844073_chk'
  tag severity: 'medium'
  tag gid: 'V-254014'
  tag rid: 'SV-254014r844075_rule'
  tag stig_id: 'JUEX-RT-000420'
  tag gtitle: 'SRG-NET-000205-RTR-000005'
  tag fix_id: 'F-57417r844074_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
