control 'SV-230049' do
  title 'The Cisco perimeter router must be configured to drop IPv6 undetermined transport packets.'
  desc 'One of the fragmentation weaknesses known in IPv6 is the undetermined transport packet. This packet contains an undetermined protocol due to fragmentation. Depending on the length of the IPv6 extension header chain, the initial fragment may not contain the layer four port information of the packet.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 undetermined transport packets.

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface interface gigabitethernet 0/2/0/2
 ipv6 address 2001::1:0:22/64
 ipv6 access-group FILTER_IPV6 ingress

Step 2: Verify that the ACL drops undetermined transport packets as shown in the example below.

ipv6 access-list FILTER_IPV6
 10 deny ipv6 any any log undetermined-transport
 20 permit ipv6 …
 …
 …
 …
 90 deny ipv6 any any log

If the router is not configured to drop IPv6 undetermined transport packets, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 undetermined transport packets as shown in the example below.
RP/0/0/CPU0:R3(config)# ipv6 access-list FILTER_IPV6
RP/0/0/CPU0:R3(config-ipv6-acl)# deny ipv6 any any undetermined-transport log
RP/0/0/CPU0:R3(config-ipv6-acl)# permit ipv6 …
…
…
…
RP/0/0/CPU0:R3(config-ipv6-acl)# deny ipv6 any any log
RP/0/0/CPU0:R3(config-ipv6-acl)# exit
RP/0/0/CPU0:R3(config)# interface gigabitethernet 0/2/0/2
RP/0/0/CPU0:R3(config-if)# ipv6 access-group FILTER_IPV6 ingress'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-32356r533186_chk'
  tag severity: 'medium'
  tag gid: 'V-230049'
  tag rid: 'SV-230049r533189_rule'
  tag stig_id: 'CISC-RT-000392'
  tag gtitle: 'SRG-NET-000364-RTR-000200'
  tag fix_id: 'F-32334r533188_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
