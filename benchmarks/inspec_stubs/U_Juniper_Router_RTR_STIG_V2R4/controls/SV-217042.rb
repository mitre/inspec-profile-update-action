control 'SV-217042' do
  title 'The Juniper perimeter router must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a router, it allows that router to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on router interfaces that do not require it, unless the router is being used as a LAN bridge.'
  desc 'check', 'Review the router configuration to determine if IP Proxy ARP is disabled on all external interfaces.

interfaces {
     description "NIPRNet";
    ge-0/0/0 {
        unit 0 {
            proxy-arp restricted;
            family inet {

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Disable Proxy ARP on all external interfaces as shown in the example below.

[edit interfaces em0 unit 0]
delete proxy-arp restricted'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18271r296994_chk'
  tag severity: 'medium'
  tag gid: 'V-217042'
  tag rid: 'SV-217042r604135_rule'
  tag stig_id: 'JUNI-RT-000370'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-18269r296995_fix'
  tag 'documentable'
  tag legacy: ['SV-101079', 'V-90869']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
