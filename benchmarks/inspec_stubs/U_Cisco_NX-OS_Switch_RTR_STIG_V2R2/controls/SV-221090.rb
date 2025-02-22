control 'SV-221090' do
  title 'The Cisco perimeter switch must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc 'Packets with Bogon IP source addresses should never be allowed to traverse the IP core. Bogon IP networks are RFC1918 addresses or address blocks that have never been assigned by the IANA or have been reserved.'
  desc 'check', 'Review the switch configuration to verify that an ingress ACL applied to all external interfaces is blocking packets with Bogon source addresses.

Step 1: Verify an ACL has been configured containing the current Bogon prefixes as shown in the example below:

ip access-list EXTERNAL_ACL
 10 deny ip 0.0.0.0/8 any log 
 20 deny ip 10.0.0.0/8 any log 
 30 deny ip 100.64.0.0/10 any log 
 40 deny ip 127.0.0.0/8 any log 
 50 deny ip 169.254.0.0/16 any log 
 60 deny ip 172.16.0.0/12 any log 
 70 deny ip 192.0.0.0/24 any log 
 80 deny ip 192.0.2.0/24 any log 
 90 deny ip 192.168.0.0/16 any log 
 100 deny ip 198.18.0.0/15 any log 
 110 deny ip 198.51.100.0/24 any log 
 120 deny ip 203.0.113.0/24 any log 
 130 deny ip 224.0.0.0/3 any log 
 140 permit tcp any any established 
 150 permit …
 …
 …
 …
210 deny ip any any log

Step 2: Verify that the inbound ACL applied to all external interfaces will block all traffic from Bogon source addresses.

interface Ethernet2/2
 description link to DISN
 no switchport
 ip access-group EXTERNAL_ACL in

If the switch is not configured to block inbound packets with source Bogon IP address prefixes, this is a finding.'
  desc 'fix', 'Configure the perimeter to block inbound packets with Bogon source addresses.

Step 1: Configure an ACL containing the current Bogon prefixes as shown below:

SW1(config)# ip access-list EXTERNAL_ACL
SW1(config-acl)# deny ip 0.0.0.0 0.255.255.255 any log
SW1(config-acl)# deny ip 10.0.0.0 0.255.255.255 any log
SW1(config-acl)# deny ip 100.64.0.0 0.63.255.255 any log
SW1(config-acl)# deny ip 127.0.0.0 0.255.255.255 any log
SW1(config-acl)# deny ip 169.254.0.0 0.0.255.255 any log
SW1(config-acl)# deny ip 172.16.0.0 0.15.255.255 any log
SW1(config-acl)# deny ip 192.0.0.0 0.0.0.255 any log
SW1(config-acl)# deny ip 192.0.2.0 0.0.0.255 any log
SW1(config-acl)# deny ip 192.168.0.0 0.0.255.255 any log
SW1(config-acl)# deny ip 198.18.0.0 0.1.255.255 any log
SW1(config-acl)# deny ip 198.51.100.0 0.0.0.255 any log
SW1(config-acl)# deny ip 203.0.113.0 0.0.0.255 any log
SW1(config-acl)# deny ip 224.0.0.0 31.255.255.255 any log
SW1(config-acl)# deny ip 240.0.0.0 31.255.255.255 any log
SW1(config-acl)# permit tcp any any established
SW1(config-acl)# permit …
…
…
…
SW1(config-acl)# deny ip any any log
SW1(config-acl)# end

Step 2: Apply the ACL inbound on all external interfaces.

SW1(config)#int e2/2
SW1(config-if)# ip access-group EXTERNAL_ACL in
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22805r409759_chk'
  tag severity: 'medium'
  tag gid: 'V-221090'
  tag rid: 'SV-221090r856649_rule'
  tag stig_id: 'CISC-RT-000270'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-22794r409760_fix'
  tag 'documentable'
  tag legacy: ['SV-110999', 'V-101895']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
