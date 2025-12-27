control 'SV-253986' do
  title 'The Juniper router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the multicast topology diagram and determine if router interfaces are enabled for IPv4 or IPv6 multicast routing.

By default, PIM is not enabled on any interface. If not a PIM router, verify there is no PIM stanza at [edit protocols], PIM is disabled globally and/or for all interfaces, or that the stanza is inactive.
[edit protocols]
inactive: pim { << Stanza is removed or marked inactive
    disable; << If stanza is present and not inactive, verify globally disabled
    interface all { << If stanza is present, not inactive, and not globally disabled, disable for all interfaces
        disable;
    }
}

For PIM routers, verify only the required interfaces are configured. For example, the following configuration enables PIM on a specific interface and disables PIM for all others.
[edit protocols]
pim {
    interface <name>.<logical unit>;
    interface all {
        disable;
    }
}

Note: More specific interface configuration statements are preferred. In the example, the interface configuration is more specific than interface "all", so PIM is enabled only on that interface.

If the router is enabled for multicast routing, verify all interfaces enabled for PIM have a neighbor filter bound to the interface. The neighbor filter must only accept PIM control plane traffic from the documented PIM neighbors.
[edit policy-options]
prefix-list PIM-NEIGHBOR-1 {
    <PIM neighbor address>/32;
}
<additional PIM neighbor lists>
policy-statement PIM-NBR-1 {
    from {
        prefix-list PIM-NEIGHBOR-1;
    }
    then accept;
}
<additional policies>
[edit protocols pim]
interface <interface name>.<logical unit> {
    mode sparse;
    neighbor-policy PIM-NBR1;
}
interface all {
    disable;
}

If PIM neighbor filters are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM enabled interfaces.

set policy-options prefix-list PIM-NEIGHBOR-1 <PIM neighbor address>/32
set policy-options policy-statement PIM-NBR-1 from prefix-list PIM-NEIGHBOR-1
set policy-options policy-statement PIM-NBR-1 then accept

set protocols pim interface <interface name>.<logical unit> mode sparse
set protocols pim interface <interface name>.<logical unit> neighbor-policy PIM-NBR-1
set protocols pim interface all disable'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57438r843989_chk'
  tag severity: 'medium'
  tag gid: 'V-253986'
  tag rid: 'SV-253986r843991_rule'
  tag stig_id: 'JUEX-RT-000140'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-57389r843990_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
