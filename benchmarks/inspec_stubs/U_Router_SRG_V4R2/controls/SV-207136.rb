control 'SV-207136' do
  title 'The perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that the ingress ACL is bound to the external interface in an inbound direction.

If the router is not configured to filter traffic entering the network at the external interface in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Bind the ingress ACL to the external interface (inbound).'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7397r382346_chk'
  tag severity: 'medium'
  tag gid: 'V-207136'
  tag rid: 'SV-207136r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000004'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7397r382347_fix'
  tag 'documentable'
  tag legacy: ['SV-92951', 'V-78245']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
