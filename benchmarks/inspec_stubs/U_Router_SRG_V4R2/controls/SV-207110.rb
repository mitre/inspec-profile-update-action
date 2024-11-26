control 'SV-207110' do
  title 'The multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the multicast topology diagram and determine if router interfaces are enabled for IPv4 or IPv6 multicast routing.

If the router is enabled for multicast routing, verify all interfaces enabled for PIM have a neighbor filter bound to the interface. The neighbor filter must only accept PIM control plane traffic from the documented PIM neighbors.

If PIM neighbor filters are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM enabled interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7371r382175_chk'
  tag severity: 'medium'
  tag gid: 'V-207110'
  tag rid: 'SV-207110r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000004'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7371r382176_fix'
  tag 'documentable'
  tag legacy: ['V-55727', 'SV-69981']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
