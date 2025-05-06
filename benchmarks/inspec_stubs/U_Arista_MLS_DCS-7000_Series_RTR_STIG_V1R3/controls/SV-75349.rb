control 'SV-75349' do
  title 'The Arista Multilayer Switch must bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'Protocol Independent Multicast (PIM) is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. Protocol Independent Multicast traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain and discover and use the rendezvous points and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'Review the multicast topology diagram and determine if router interfaces are enabled for IPv4 or IPv6 multicast routing.

If the router is enabled for multicast routing, verify all interfaces enabled for PIM have a neighbor filter bound to the interface. The neighbor filter must only accept PIM control plane traffic from the documented PIM neighbors. To verify a neighbor filter is active, execute the "show running-config" command and find the "ip pim neighbor-filter [name]" statement in the interface configuration mode.

If PIM neighbor filters are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM-enabled interfaces.

To create a new neighbor filter, create an access list by entering:

ip access-list [name]
[ip access list permit/deny statement]
exit

Then apply the neighbor filter based on the accesslist to the PIM-enabled interface:

int ethernet 1
ip pim neighbor-filter [name-of-ACL]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60891'
  tag rid: 'SV-75349r1_rule'
  tag stig_id: 'AMLS-L3-000120'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-66603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
