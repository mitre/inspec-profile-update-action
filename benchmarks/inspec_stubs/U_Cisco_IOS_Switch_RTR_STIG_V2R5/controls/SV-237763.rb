control 'SV-237763' do
  title 'The Cisco perimeter switch must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3-255.'
  desc 'The routing header can be used maliciously to send a packet through a path where less robust security is in place, rather than through the presumably preferred path of routing protocols. Use of the routing extension header has few legitimate uses other than as implemented by Mobile IPv6. 

The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to spoof source addresses and obtain traffic in response, rather than the real owner of the address. Secondly, a packet with an allowed destination address could be sent through a Firewall using the Routing Header functionality, only to bounce to a different node once inside. The Type 1 Routing Header is defined by a specification called "Nimrod Routing", a discontinued project funded by DARPA. Assuming that most implementations will not recognize the Type 1 Routing Header, it must be dropped. The Type 3–255 Routing Header values in the routing type field are currently undefined and should be dropped inbound and outbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the switch configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255.

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface gigabitethernet1/0
 ipv6 address 2001::1:0:22/64
 ipv6 traffic-filter FILTER_IPV6 in


Step 2: Verify that the ACL drops IPv6 packets with a Routing Header type 0, 1, or 3-255 
as shown in the example below.

ipv6 access-list FILTER_IPV6
 permit ipv6 any host 2001:DB8::1:1:1234 routing-type 2
 deny ipv6 any any log routing
 permit ipv6 …
 …
 …
 …
deny ipv6 any any log

Note: The example above allows routing-type 2 in the event Mobility IPv6 is deployed.

If the switch is not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255, this is a finding.'
  desc 'fix', 'Configure the switch to drop IPv6 packets with Routing Header of type 0, 1, or 3-255 as shown in the example below.
SW1(config)#ipv6 access-list FILTER_IPV6
SW1(config-ipv6-acl)#permit ipv6 any host 2001:DB8::0:1:1:1234 routing-type 2
SW1(config-ipv6-acl)#deny ipv6 any any routing log
SW1(config-ipv6-acl)#permit …
…
…
…
SW1(config-ipv6-acl)#deny ipv6 any any log
SW1(config-ipv6-acl)#exit
SW1(config)#int g1/0
SW1(config-if)#ipv6 traffic-filter FILTER_IPV6'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-40977r856256_chk'
  tag severity: 'medium'
  tag gid: 'V-237763'
  tag rid: 'SV-237763r856665_rule'
  tag stig_id: 'CISC-RT-000393'
  tag gtitle: 'SRG-NET-000364-RTR-000201'
  tag fix_id: 'F-40939r856257_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
