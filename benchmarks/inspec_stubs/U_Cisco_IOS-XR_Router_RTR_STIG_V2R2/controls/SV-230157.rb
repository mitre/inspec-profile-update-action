control 'SV-230157' do
  title 'The Cisco perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large. This option type from RFC 1888 (OSI NSAPs and IPv6) has been deprecated by RFC 4048.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop IPv6 packets containing the NSAP address option within Destination Option header. 

Step 1: Verify that an inbound IPv6 ACL has been configured on the external interface.

interface interface gigabitethernet 0/2/0/2
 ipv6 address 2001::1:0:22/64
 ipv6 access-group FILTER_IPV6 ingress

Step 2: Verify that the ACL drops IPv6 packets containing the NSAP address option within Destination Option header as shown in the example below.

ipv6 access-list FILTER_IPV6
 10 deny 60 any any dest-option-type 195 log
 20 permit ipv6 …
 …
 …
 …
 90 deny ipv6 any any log

If the router is not configured to drop IPv6 packets containing the NSAP address option within Destination Option header, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing a Destination Option header with option type value of 0xC3 (NSAP address) as shown in the example below.

RP/0/0/CPU0:R3(config)# ipv6 access-list FILTER_IPV6
RP/0/0/CPU0:R3(config-ipv6-acl)# deny 60 any any dest-option-type 195 log
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
  tag check_id: 'C-32470r856480_chk'
  tag severity: 'medium'
  tag gid: 'V-230157'
  tag rid: 'SV-230157r856673_rule'
  tag stig_id: 'CISC-RT-000397'
  tag gtitle: 'SRG-NET-000364-RTR-000205'
  tag fix_id: 'F-32448r856481_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
