control 'SV-237772' do
  title 'The Cisco perimeter switch must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.'
  desc 'These options are intended to be for the Hop-by-Hop header only. The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize. Hence, this could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the switch configuration to determine if it is compliant with this requirement.  

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface gigabitethernet1/0
 ipv6 address 2001::1:0:22/64
 ipv6 traffic-filter FILTER_IPV6 in


Step 2: Verify that the ACL drops IPv6 packets containing a Destination Option header with option type values of 0x05 (Switch Alert) or 0xC2 (Jumbo Payload) as shown in the example below.

ipv6 access-list FILTER_IPV6
 deny 60 any any dest-option-type 5 log
 deny 60 any any dest-option-type 194 log
 permit ipv6 …
 …
 …
 …
 deny ipv6 any any log

If the switch is not configured to drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Switch Alert) or 0xC2 (Jumbo Payload), this is a finding.'
  desc 'fix', 'Configure the switch to drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Switch Alert) or 0xC2 (Jumbo Payload) as shown in the example below.

SW1(config)#ipv6 access-list FILTER_IPV6
SW1(config-ipv6-acl)#deny 60 any any dest-option-type 5 log
SW1(config-ipv6-acl)#deny 60 any any dest-option-type 194 log
SW1(config-ipv6-acl)#permit …
…
…
…
SW1(config-ipv6-acl)#deny ipv6 any any log
SW1(config-ipv6-acl)#exit
SW1(config)#int g1/0
SW1(config-if)#ipv6 traffic-filter FILTER_IPV6
SW1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-40985r648808_chk'
  tag severity: 'medium'
  tag gid: 'V-237772'
  tag rid: 'SV-237772r648811_rule'
  tag stig_id: 'CISC-RT-000395'
  tag gtitle: 'SRG-NET-000364-RTR-000203'
  tag fix_id: 'F-40944r648809_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
