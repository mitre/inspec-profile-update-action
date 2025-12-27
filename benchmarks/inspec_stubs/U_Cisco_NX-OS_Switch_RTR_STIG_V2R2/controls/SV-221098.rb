control 'SV-221098' do
  title 'The Cisco perimeter switch must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a switch, it allows that switch to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on switch interfaces that do not require it, unless the switch is being used as a LAN bridge.'
  desc 'check', 'Review the switch configuration to determine if IP Proxy ARP is enabled on any external interface as shown in the example below:

interface Ethernet2/2
 description link to DISN
 no switchport
 ip address x.1.12.2/24
 ip proxy-arp
 no shutdown

Note: By default Proxy ARP is disabled on all interfaces.

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable Proxy ARP on all external interfaces as shown in the example below:

SW1(config)#int e2/2 
SW1(config-if)# no ip proxy-arp
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22813r409783_chk'
  tag severity: 'medium'
  tag gid: 'V-221098'
  tag rid: 'SV-221098r856651_rule'
  tag stig_id: 'CISC-RT-000380'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-22802r409784_fix'
  tag 'documentable'
  tag legacy: ['SV-111015', 'V-101911']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
