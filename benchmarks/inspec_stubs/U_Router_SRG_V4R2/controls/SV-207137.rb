control 'SV-207137' do
  title 'The perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone. 

Review the router configuration to verify that the egress ACL is bound to the internal interface in an inbound direction. 

If the router is not configured to filter traffic leaving the network at the internal interface in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure an egress ACL bound to the internal interface in an inbound direction to filter traffic leaving the network.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7398r382349_chk'
  tag severity: 'medium'
  tag gid: 'V-207137'
  tag rid: 'SV-207137r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000005'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7398r382350_fix'
  tag 'documentable'
  tag legacy: ['V-78247', 'SV-92953']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
