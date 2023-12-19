control 'SV-256044' do
  title 'The Arista perimeter router must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

The Arista perimeter router of the managed network must be configured with an access control list (ACL) or filter on the egress interface to block all management traffic.

Step 1: To verify the configuration is blocking all outbound traffic destined to management network, execute the command "sh ip access-list".

ip access-list FILTER_MANAGEMENT_SUBNET
  deny ip any 172.20.1.0 0.0.0.255 log
  permit ip any any

Step 2: To verify the filter is applied on egress interface, execute the command "sh run int ethernet YY".

interface ethernet 3
ip access-group FILTER_MANAGEMENT_SUBNET out

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista perimeter router of the managed network with an ACL or filter on the egress interface to block all outbound management traffic.

Step 1: Configure the filter to block all outbound traffic destined to the management network.

LEAF-1A(config-if-Et3)#ip access-list FILTER_MANAGEMENT_SUBNET
LEAF-1A(config-acl-FILTER_MANAGEMENT_SUBNET)#  deny ip any 172.20.1.0 0.0.0.255 log
LEAF-1A(config-acl-FILTER_MANAGEMENT_SUBNET)#  permit ip any any

Step 2: Apply the filter egress on the interface.

LEAF-1A(config-acl-FILTER_MANAGEMENT_SUBNET)#interface ethernet 3
LEAF-1A(config-if-Et3)#ip access-group FILTER_MANAGEMENT_SUBNET out'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59720r882472_chk'
  tag severity: 'medium'
  tag gid: 'V-256044'
  tag rid: 'SV-256044r882474_rule'
  tag stig_id: 'ARST-RT-000650'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-59663r882473_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
