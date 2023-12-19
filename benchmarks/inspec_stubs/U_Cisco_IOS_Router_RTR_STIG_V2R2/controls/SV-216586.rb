control 'SV-216586' do
  title 'The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a router, it allows that router to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on router interfaces that do not require it, unless the router is being used as a LAN bridge.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if IP Proxy ARP is disabled on all external interfaces as shown in the example below.

interface GigabitEthernet0/1
 description link to DISN
 ip address x.1.12.2 255.255.255.252
 no ip proxy-arp

Note: By default Proxy ARP is enabled on all interfaces; hence, if enabled, it will not be shown in the configuration. 

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Disable Proxy ARP on all external interfaces as shown in the example below.

R2(config)#int g0/1     
R2(config-if)#no ip proxy-arp'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17821r287136_chk'
  tag severity: 'medium'
  tag gid: 'V-216586'
  tag rid: 'SV-216586r856191_rule'
  tag stig_id: 'CISC-RT-000380'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-17817r287137_fix'
  tag 'documentable'
  tag legacy: ['SV-105711', 'V-96573']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
