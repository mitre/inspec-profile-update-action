control 'SV-256043' do
  title 'The Arista perimeter router must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a Cisco router, it allows that router to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on router interfaces that do not require it unless the router is being used as a LAN bridge.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration to determine if IP Proxy ARP is disabled on all external interfaces. Execute the command "sh run int ethernet YY".

int ethernet 3
no ip proxy-arp 

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Disable IP Proxy ARP on all external interfaces.

LEAF-1A(config)#int ethernet 3
LEAF-1A(config-if-Et3)#no ip proxy-arp'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59719r882469_chk'
  tag severity: 'medium'
  tag gid: 'V-256043'
  tag rid: 'SV-256043r882471_rule'
  tag stig_id: 'ARST-RT-000640'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-59662r882470_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
