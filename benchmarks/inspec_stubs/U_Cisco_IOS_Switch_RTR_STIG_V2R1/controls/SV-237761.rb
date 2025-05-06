control 'SV-237761' do
  title 'The Cisco perimeter switch must be configured to drop IPv6 undetermined transport packets.'
  desc 'One of the fragmentation weaknesses known in IPv6 is the undetermined transport packet. This packet contains an undetermined protocol due to fragmentation. Depending on the length of the IPv6 extension header chain, the initial fragment may not contain the layer four port information of the packet.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the switch configuration to determine if it is configured to drop IPv6 undetermined transport packets.

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface gigabitethernet1/0
 ipv6 address 2001::1:0:22/64
 ipv6 traffic-filter FILTER_IPV6 in


Step 2: Verify that the ACL drops undetermined transport packets as shown in the example below.

ipv6 access-list FILTER_IPV6
 deny ipv6 any any log undetermined-transport
 permit ipv6 …
 …
 …
 …
 deny ipv6 any any log

If the switch is not configured to drop IPv6 undetermined transport packets, this is a finding.'
  desc 'fix', 'Configure the switch to drop IPv6 undetermined transport packets as shown in the example below.

SW1(config)#ipv6 access-list FILTER_IPV6
SW1(config-ipv6-acl)#deny ipv6 any any undetermined-transport log
SW1(config-ipv6-acl)#permit ipv6 …
…
…
…
SW1(config-ipv6-acl)#deny ipv6 any any log
SW1(config-ipv6-acl)#exit
SW1(config)#int g1/0
SW1(config-if)#ipv6 traffic-filter FILTER_IPV6 in'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-40976r648796_chk'
  tag severity: 'medium'
  tag gid: 'V-237761'
  tag rid: 'SV-237761r648798_rule'
  tag stig_id: 'CISC-RT-000392'
  tag gtitle: 'SRG-NET-000364-RTR-000200'
  tag fix_id: 'F-40938r648797_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
