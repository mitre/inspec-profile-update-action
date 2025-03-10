control 'SV-207167' do
  title 'The perimeter router must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

The perimeter router of the managed network must be configured with an access control list (ACL) or filter on the egress interface to block all management traffic.

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the perimeter router of the managed network with an ACL or filter on the egress interface to block all outbound management traffic.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7428r382529_chk'
  tag severity: 'medium'
  tag gid: 'V-207167'
  tag rid: 'SV-207167r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000113'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7428r382530_fix'
  tag 'documentable'
  tag legacy: ['SV-92959', 'V-78253']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
