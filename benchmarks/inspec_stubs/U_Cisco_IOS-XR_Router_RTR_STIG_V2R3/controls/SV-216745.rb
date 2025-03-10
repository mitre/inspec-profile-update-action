control 'SV-216745' do
  title 'The Cisco router must be configured to have IP directed broadcast disabled on all interfaces.'
  desc 'An IP directed broadcast is a datagram sent to the broadcast address of a subnet that is not directly attached to the sending machine. The directed broadcast is routed through the network as a unicast packet until it arrives at the target subnet, where it is converted into a link-layer broadcast. Because of the nature of the IP addressing architecture, only the last router in the chain, which is connected directly to the target subnet, can conclusively identify a directed broadcast.

IP directed broadcasts are used in the extremely common and popular smurf, or denial-of-service (DoS), attacks. In a smurf attack, the attacker sends Internet Control Message Protocol (ICMP) echo requests from a falsified source address to a directed broadcast address, causing all the hosts on the target subnet to send replies to the falsified source. By sending a continuous stream of such requests, the attacker can create a much larger stream of replies, which can completely inundate the host whose address is being falsified. This service should be disabled on all interfaces when not needed to prevent smurf and DoS attacks.

Directed broadcast can be enabled on internal facing interfaces to support services such as Wake-On-LAN. Case scenario may also include support for legacy applications where the content server and the clients do not support multicast. The content servers send streaming data using UDP broadcast. Used in conjunction with the IP multicast helper-map feature, broadcast data can be sent across a multicast topology. The broadcast streams are converted to multicast and vice versa at the first-hop routers and last-hop routers before entering and leaving the multicast transit area respectively. The last-hop router must convert the multicast to broadcast. Hence, this interface must be configured to forward a broadcast packet (i.e., a directed broadcast address is converted to the all nodes broadcast address).'
  desc 'check', 'Review the router configuration to determine if it is compliant with this requirement. IP directed broadcast command must not be found on any interface as shown in the example below.

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 directed-broadcast

If IP directed broadcast is not disabled on all interfaces, this is a finding.'
  desc 'fix', 'Disable IP directed broadcast on all interfaces as shown in the example below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1
RP/0/0/CPU0:R3(config-if)#no ipv4 directed-broadcast'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17977r288624_chk'
  tag severity: 'low'
  tag gid: 'V-216745'
  tag rid: 'SV-216745r856436_rule'
  tag stig_id: 'CISC-RT-000160'
  tag gtitle: 'SRG-NET-000362-RTR-000112'
  tag fix_id: 'F-17975r288625_fix'
  tag 'documentable'
  tag legacy: ['SV-105835', 'V-96697']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
