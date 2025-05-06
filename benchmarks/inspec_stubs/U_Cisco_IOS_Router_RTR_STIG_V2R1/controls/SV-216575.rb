control 'SV-216575' do
  title 'The Cisco perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc 'Packets with Bogon IP source addresses should never be allowed to traverse the IP core. Bogon IP networks are RFC1918 addresses or address blocks that have never been assigned by the IANA or have been reserved.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that an ingress Access Control List (ACL) applied to all external interfaces is blocking packets with Bogon source addresses.

Step 1: Verify an ACL has been configured containing the current Bogon prefixes as shown in the example below.

ip access-list extended FILTER_PERIMETER
 deny   ip 0.0.0.0 0.255.255.255 any log-input
 deny   ip 10.0.0.0 0.255.255.255 any log-input
 deny   ip 100.64.0.0 0.63.255.255 any log-input
 deny   ip 127.0.0.0 0.255.255.255 any log-input
 deny   ip 169.254.0.0 0.0.255.255 any log-input
 deny   ip 172.16.0.0 0.15.255.255 any log-input
 deny   ip 192.0.0.0 0.0.0.255 any log-input
 deny   ip 192.0.2.0 0.0.0.255 any log-input
 deny   ip 192.168.0.0 0.0.255.255 any log-input
 deny   ip 198.18.0.0 0.1.255.255 any log-input
 deny   ip 198.51.100.0 0.0.0.255 any log-input
 deny   ip 203.0.113.0 0.0.0.255 any log-input
 deny   ip 224.0.0.0 31.255.255.255 any log-input
 permit tcp any any established
 permit tcp host x.12.1.9 host x.12.1.10 eq bgp
 permit tcp host x.12.1.9 eq bgp host x.12.1.10
 permit icmp host x.12.1.9 host x.12.1.10 echo
 permit icmp host x.12.1.9 host x.12.1.10 echo-reply
 …
 …
 …
 deny   ip any any log-input

Step 2: Verify that the inbound ACL applied to all external interfaces will block all traffic from Bogon source addresses.

interface GigabitEthernet0/1
 description Link to DISN
 ip address x.12.1.10 255.255.255.254
 ip access-group FILTER_PERIMETER in

If the router is not configured to block inbound packets with source Bogon IP address prefixes, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the perimeter to block inbound packets with Bogon source addresses.

Step 1: Configure an ACL containing the current Bogon prefixes as shown below.

R5(config)#ip access-list extended FILTER_PERIMETER
R5(config-ext-nacl)#deny ip 0.0.0.0 0.255.255.255 any log-input
R5(config-ext-nacl)#deny ip 10.0.0.0 0.255.255.255 any log-input
R5(config-ext-nacl)#deny ip 100.64.0.0 0.63.255.255 any log-input
R5(config-ext-nacl)#deny ip 127.0.0.0 0.255.255.255 any log-input
R5(config-ext-nacl)#deny ip 169.254.0.0 0.0.255.255 any log-input
R5(config-ext-nacl)#deny ip 172.16.0.0 0.15.255.255 any log-input
R5(config-ext-nacl)#deny ip 192.0.0.0 0.0.0.255 any log-input
R5(config-ext-nacl)#deny ip 192.0.2.0 0.0.0.255 any log-input
R5(config-ext-nacl)#deny ip 192.168.0.0 0.0.255.255 any log-input
R5(config-ext-nacl)#deny ip 198.18.0.0 0.1.255.255 any log-input
R5(config-ext-nacl)#deny ip 198.51.100.0 0.0.0.255 any log-input
R5(config-ext-nacl)#deny ip 203.0.113.0 0.0.0.255 any log-input
R5(config-ext-nacl)#deny ip 224.0.0.0 31.255.255.255 any log-input
R5(config-ext-nacl)#deny ip 240.0.0.0 31.255.255.255 any log-input
R5(config-ext-nacl)#permit tcp any any established
R5(config-ext-nacl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp
R5(config-ext-nacl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10
R5(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo
R5(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply
…
…
…
R5(config-ext-nacl)#deny ip any any log-input
R5(config-ext-nacl)#end

Step 2: Apply the ACL inbound on all external interfaces.

R2(config)#int g0/0
R1(config-if)#ip access-group  FILTER_PERIMETER in
R1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17810r287109_chk'
  tag severity: 'medium'
  tag gid: 'V-216575'
  tag rid: 'SV-216575r531085_rule'
  tag stig_id: 'CISC-RT-000270'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-17806r287110_fix'
  tag 'documentable'
  tag legacy: ['V-96551', 'SV-105689']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
