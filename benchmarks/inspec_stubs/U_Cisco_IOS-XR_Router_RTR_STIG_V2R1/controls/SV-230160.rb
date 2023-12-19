control 'SV-230160' do
  title 'The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop all inbound IPv6 packets containing an undefined option type value regardless of whether they appear in a Hop-by-Hop or Destination Option header. Undefined values are 0x02, 0x03, 0x06, 0x9 – 0xE, 0x10 – 0x22, 0x24, 0x25, 0x27 – 0x2F, and 0x31 – 0xFF.

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface interface gigabitethernet 0/2/0/2
 ipv6 address 2001::1:0:22/64
 ipv6 access-group FILTER_IPV6 ingress

Step 2: Verify that the ACL drops IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type as shown in the example below.

ipv6 access-list FILTER_IPV6
 10 deny any any dest-option-type 2
 20 deny any any dest-option-type 3
 30 deny any any dest-option-type 6
 40 deny any any dest-option-type 9
 50 deny any any dest-option-type 10
 60 deny any any dest-option-type 11
 70 deny any any dest-option-type 12
 80 deny any any dest-option-type 13
 90 deny any any dest-option-type 14
 100 deny any any dest-option-type 16
  …
 280 deny any any dest-option-type 34
 290 deny any any dest-option-type 36
 300 deny any any dest-option-type 37
 310 deny any any dest-option-type 39
 …
 390 deny any any dest-option-type 47
 400 deny any any dest-option-type 49
 … 
 nnn deny any any dest-option-type 255
 nnn permit  …
 …
 …
 …
 nnn deny ipv6 any any log

Note: Because hop-by-hop and destination options have the same exact header format, they can be combined under the dest-option-type keyword. Since Hop-by-Hop and Destination Option headers have non-overlapping types, you can use dest-option-type to match either.

If the router is not configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type, this is a finding.'
  desc 'fix', 'Configure the router to drop all inbound IPv6 packets containing an undefined option type value regardless of whether they appear in a Hop-by-Hop or Destination Option header as shown in the example below.

RP/0/0/CPU0:R3(config)# ipv6 access-list FILTER_IPV6
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 2
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 3
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 6
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 9
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 10
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 11
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 12
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 13
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 14
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 16
 …
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 34
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 36
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 37
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 39
…
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 47
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 49
… 
RP/0/0/CPU0:R3(config-ipv6-acl)# deny any any dest-option-type 255
RP/0/0/CPU0:R3(config-ipv6-acl)# permit ipv6 …
…
…
…
RP/0/0/CPU0:R3(config-ipv6-acl)# deny ipv6 any any log
RP/0/0/CPU0:R3(config-ipv6-acl)# exit
RP/0/0/CPU0:R3(config)# interface gigabitethernet 0/2/0/2
RP/0/0/CPU0:R3(config-if)# ipv6 access-group FILTER_IPV6 ingress
RP/0/0/CPU0:R3(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-32472r538616_chk'
  tag severity: 'medium'
  tag gid: 'V-230160'
  tag rid: 'SV-230160r538618_rule'
  tag stig_id: 'CISC-RT-000398'
  tag gtitle: 'SRG-NET-000364-RTR-000206'
  tag fix_id: 'F-32450r538617_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
