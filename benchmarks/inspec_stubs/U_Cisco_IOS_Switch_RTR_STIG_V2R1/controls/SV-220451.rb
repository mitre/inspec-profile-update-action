control 'SV-220451' do
  title 'The Cisco perimeter switch must be configured to have Proxy ARP disabled on all external interfaces.'
  desc 'When Proxy ARP is enabled on a switch, it allows that switch to extend the network (at Layer 2) across multiple interfaces (LAN segments). Because proxy ARP allows hosts from different LAN segments to look like they are on the same segment, proxy ARP is only safe when used between trusted LAN segments. 

Attackers can leverage the trusting nature of proxy ARP by spoofing a trusted host and then intercepting packets. Proxy ARP should always be disabled on switch interfaces that do not require it unless the switch is being used as a LAN bridge.'
  desc 'check', 'Review the switch configuration to determine if IP Proxy ARP is disabled on all external interfaces as shown in the example below: 

interface GigabitEthernet0/1 
 description link to DISN 
 ip address x.1.12.2 255.255.255.252 
 no ip proxy-arp 

Note: By default, Proxy ARP is enabled on all interfaces; hence, if enabled, it will not be shown in the configuration. 

If IP Proxy ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable Proxy ARP on all external interfaces as shown in the example below: 

SW1(config)#int g0/1 
SW1(config-if)#no ip proxy-arp'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22166r508432_chk'
  tag severity: 'medium'
  tag gid: 'V-220451'
  tag rid: 'SV-220451r622190_rule'
  tag stig_id: 'CISC-RT-000380'
  tag gtitle: 'SRG-NET-000364-RTR-000112'
  tag fix_id: 'F-22155r508433_fix'
  tag 'documentable'
  tag legacy: ['SV-110749', 'V-101645']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
