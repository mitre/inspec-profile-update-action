control 'SV-207166' do
  title 'The perimeter router must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a Cisco router, it allows that router to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on router interfaces that do not require it, unless the router is being used as a LAN bridge.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to determine if IP Proxy ARP is disabled on all external interfaces.

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Disable IP Proxy ARP on all external interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7427r382526_chk'
  tag severity: 'medium'
  tag gid: 'V-207166'
  tag rid: 'SV-207166r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000112'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7427r382527_fix'
  tag 'documentable'
  tag legacy: ['SV-92957', 'V-78251']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
