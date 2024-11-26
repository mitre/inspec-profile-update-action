control 'SV-256031' do
  title 'The Arista router must be configured to have IP directed broadcast disabled on all interfaces.'
  desc "An IP-directed broadcast is a datagram sent to the broadcast address of a subnet that is not directly attached to the sending machine. The directed broadcast is routed through the network as a unicast packet until it arrives at the target subnet, where it is converted into a link-layer broadcast. Because of the nature of the IP addressing architecture, only the last router in the chain, which is connected directly to the target subnet, can conclusively identify a directed broadcast.

IP-directed broadcasts are used in the extremely common and popular smurf, or denial-of-service (DoS) attacks. In a smurf attack, the attacker sends Internet Control Message Protocol (ICMP) echo requests from a falsified source address to a directed broadcast address, causing all the hosts on the target subnet to send replies to the falsified source. By sending a continuous stream of such requests, the attacker can create a much larger stream of replies, which can completely inundate the host whose address is being falsified. This service should be disabled on all interfaces when not needed to prevent smurf and DoS attacks.

Directed broadcast can be enabled on internal facing interfaces to support services such as Wake-On-LAN. Case scenario may also include support for legacy applications where the content server and the clients do not support multicast. The content servers send streaming data using UDP broadcast. Used in conjunction with the IP multicast helper-map feature, broadcast data can be sent across a multicast topology. The broadcast streams are converted to multicast and vice versa at the first-hop routers and last-hop routers before entering and leaving the multicast transit area respectively. The last-hop router must convert the multicast to broadcast. Hence, this interface must be configured to forward a broadcast packet (i.e., a directed broadcast address is converted to the nodes' broadcast address)."
  desc 'check', 'Review the Arista router configuration to determine if IP directed broadcast is enabled.

By default, IP directed broadcast is disabled on Arista multi-layer router. To verify the IP directed broadcast is enabled, execute the command:

 sh run int ethernet <YY>

interface Ethernet 2
 ip address 10.1.12.1/24
 no ip directed-broadcast

If IP directed broadcast is enabled on layer 3 interfaces, this is a finding.'
  desc 'fix', 'Disable IP directed broadcasts on all layer 3 interfaces.

LEAF-1A(config)#interface Ethernet 2
LEAF-1A(config-if-Et2)# ip address 10.1.12.1/24
LEAF-1A(config-if-Et2)# no ip directed-broadcast'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59707r882433_chk'
  tag severity: 'low'
  tag gid: 'V-256031'
  tag rid: 'SV-256031r884234_rule'
  tag stig_id: 'ARST-RT-000520'
  tag gtitle: 'SRG-NET-000362-RTR-000112'
  tag fix_id: 'F-59650r882434_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
