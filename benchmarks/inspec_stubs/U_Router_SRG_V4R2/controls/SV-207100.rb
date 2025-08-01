control 'SV-207100' do
  title 'The BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the Internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the router configuration to verify that there are filters defined to only accept routes for prefixes that belong to specific customers. 

The prefix filter must be referenced inbound on the appropriate BGP neighbor statement.

If the router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.'
  desc 'fix', 'Configure all eBGP routers to reject inbound route advertisements from a CE router for prefixes that are not allocated to that customer.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7361r382145_chk'
  tag severity: 'medium'
  tag gid: 'V-207100'
  tag rid: 'SV-207100r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000004'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7361r382146_fix'
  tag 'documentable'
  tag legacy: ['V-78271', 'SV-92977']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
