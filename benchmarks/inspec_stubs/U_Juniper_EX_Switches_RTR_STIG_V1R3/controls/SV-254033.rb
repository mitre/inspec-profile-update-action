control 'SV-254033' do
  title 'The Juniper router must be configured to have IP directed broadcast disabled on all interfaces.'
  desc 'An IP directed broadcast is a datagram sent to the broadcast address of a subnet that is not directly attached to the sending machine. The directed broadcast is routed through the network as a unicast packet until it arrives at the target subnet, where it is converted into a link-layer broadcast. Because of the nature of the IP addressing architecture, only the last router in the chain, which is connected directly to the target subnet, can conclusively identify a directed broadcast.

IP directed broadcasts are used in the extremely common and popular smurf, or denial-of-service (DoS), attacks. In a smurf attack, the attacker sends Internet Control Message Protocol (ICMP) echo requests from a falsified source address to a directed broadcast address, causing all the hosts on the target subnet to send replies to the falsified source. By sending a continuous stream of such requests, the attacker can create a much larger stream of replies, which can completely inundate the host whose address is being falsified. This service should be disabled on all interfaces when not needed to prevent smurf and DoS attacks.

Directed broadcast can be enabled on internal facing interfaces to support services such as Wake-On-LAN. Case scenario may also include support for legacy applications where the content server and the clients do not support multicast. The content servers send streaming data using UDP broadcast. Used in conjunction with the IP multicast helper-map feature, broadcast data can be sent across a multicast topology. The broadcast streams are converted to multicast and vice versa at the first-hop routers and last-hop routers before entering and leaving the multicast transit area respectively. The last-hop router must convert the multicast to broadcast. Hence, this interface must be configured to forward a broadcast packet (i.e., a directed broadcast address is converted to the all-nodes broadcast address).'
  desc 'check', 'Review the router configuration to determine if IP directed broadcast is enabled.

By default, IP directed broadcast is disabled on all L3 interfaces, including Integrated Routing and Bridging (IRB) interfaces. Verify "targeted-broadcast" is not enabled as shown.

[edit interfaces]
<L3 interface> {
    unit <number> {
        family inet {
            targeted-broadcast; << Must not be present.
            address <IPv4 address>/<mask>;
        }
    }
}
irb {
    unit <number> {
        family inet {
            targeted-broadcast; << Must not be present.
            address <IPv4 address>/<mask>;
        }
    }
}

If IP directed broadcast is enabled on layer 3 interfaces, this is a finding.'
  desc 'fix', 'Disable IP directed broadcasts on all layer 3 interfaces.

delete interfaces <L3 interface> unit <number> family inet targeted-broadcast
delete interfaces irb unit <L3 IRB interface> family inet targeted-broadcast'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57485r844130_chk'
  tag severity: 'low'
  tag gid: 'V-254033'
  tag rid: 'SV-254033r844132_rule'
  tag stig_id: 'JUEX-RT-000610'
  tag gtitle: 'SRG-NET-000362-RTR-000112'
  tag fix_id: 'F-57436r844131_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
