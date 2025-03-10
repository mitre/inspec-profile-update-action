control 'SV-230052' do
  title 'The Cisco perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3–255.'
  desc 'The routing header can be used maliciously to send a packet through a path where less robust security is in place, rather than through the presumably preferred path of routing protocols. Use of the routing extension header has few legitimate uses other than as implemented by Mobile IPv6. 

The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to spoof source addresses and obtain traffic in response, rather than the real owner of the address. Secondly, a packet with an allowed destination address could be sent through a Firewall using the Routing Header functionality, only to bounce to a different node once inside. The Type 1 Routing Header is defined by a specification called "Nimrod Routing", a discontinued project funded by DARPA. Assuming that most implementations will not recognize the Type 1 Routing Header, it must be dropped. The Type 3–255 Routing Header values in the routing type field are currently undefined and should be dropped inbound and outbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255.

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface interface gigabitethernet 0/2/0/2
 ipv6 address 2001::1:0:22/64
 ipv6 access-group FILTER_IPV6 ingress

Step 2: Verify that the ACL drops IPv6 packets with a Routing Header type 0, 1, or 3-255 
as shown in the example below.

ipv6 access-list FILTER_IPV6
 10 permit ipv6 any host 2001:DB8::1:1:1234 routing-type 2
 20 deny ipv6 any any log routing
 30 permit ipv6 …
 …
 …
 …
90 deny ipv6 any any log

Note: The example above allows routing-type 2 in the event Mobility IPv6 is deployed.

If the router is not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets with Routing Header of type 0, 1, or 3-255 as shown in the example below.

RP/0/0/CPU0:R3(config)# ipv6 access-list FILTER_IPV6
RP/0/0/CPU0:R3(config-ipv6-acl)# permit ipv6 any host 2001:DB8::0:1:1:1234 routing-type 2
RP/0/0/CPU0:R3(config-ipv6-acl)# deny ipv6 any any routing log
RP/0/0/CPU0:R3(config-ipv6-acl)# permit …
…
…
…
RP/0/0/CPU0:R3(config-ipv6-acl)# deny ipv6 any any log
RP/0/0/CPU0:R3(config-ipv6-acl)# exit
RP/0/0/CPU0:R3(config)# interface gigabitethernet 0/2/0/2
RP/0/0/CPU0:R3(config-if)# ipv6 access-group FILTER_IPV6 ingress'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-32358r533194_chk'
  tag severity: 'medium'
  tag gid: 'V-230052'
  tag rid: 'SV-230052r533196_rule'
  tag stig_id: 'CISC-RT-000393'
  tag gtitle: 'SRG-NET-000364-RTR-000201'
  tag fix_id: 'F-32336r533195_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
