control 'SV-207132' do
  title 'The perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that the access control list (ACL) or filter is configured to allow specific ports and protocols and deny all other traffic.

The filter must be configured inbound on all external interfaces.

If the ACL or filter is not configured to allow specific ports and protocols and deny all other traffic, this is a finding.

If the filter is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the perimeter router to deny network traffic by default and allow network traffic by exception.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7393r382334_chk'
  tag severity: 'high'
  tag gid: 'V-207132'
  tag rid: 'SV-207132r604135_rule'
  tag stig_id: 'SRG-NET-000202-RTR-000001'
  tag gtitle: 'SRG-NET-000202'
  tag fix_id: 'F-7393r382335_fix'
  tag 'documentable'
  tag legacy: ['V-78237', 'SV-92943']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
