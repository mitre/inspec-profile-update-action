control 'SV-221088' do
  title 'The Cisco perimeter switch must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most switches, internal information flow control is a product of system design.'
  desc 'check', 'Review the switch configuration to verify that ACLs are configured to allow or deny traffic for specific destination addresses as well as ports and protocols. In the example below, the switch is peering BGP with DISN. ICMP echo and echo-reply packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound to the NIPRNet host-facing web server (x.11.2.3).

Step 1: Verify that an inbound ACL is applied to all external interfaces as shown in the example below:

interface Ethernet2/2
 description link to DISN
 no switchport
 ip access-group EXTERNAL_ACL in
 ip address x.11.1.2 255.255.255.254

Step 2: Review inbound ACL to verify that it is configured to deny all other traffic that is not explicitly allowed.

ip access-list EXTERNAL_ACL
 10 permit tcp any any established 
 20 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 30 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 40 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
 50 permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
 60 permit tcp any x.11.2.3/32 eq www 
 70 permit …
 …
 …
 …
90 deny ip any any log

If the switch is not configured to enforce approved authorizations for controlling the flow of information between interconnected networks, this is a finding.'
  desc 'fix', 'Step 1: Configure an ACL to allow or deny traffic as shown in the example below:

SW2(config)# ip access-list EXTERNAL_ACL
SW2(config-acl)# permit tcp any any established
SW2(config-acl)# permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
SW2(config-acl)# permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
SW2(config-acl)# permit icmp x.11.1.1/32 x.11.1.2/32 echo 
SW2(config-acl)# permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
SW2(config-acl)# permit tcp any x.11.2.3/32 eq www 
SW2(config-acl)# deny ip any any log
SW2(config-acl)# exit

Step 2: Apply the ACL inbound on all applicable interfaces.

SW1(config)#int e2/2
SW1(config-if)# ip access-group EXTERNAL_ACL in'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22803r409753_chk'
  tag severity: 'medium'
  tag gid: 'V-221088'
  tag rid: 'SV-221088r622190_rule'
  tag stig_id: 'CISC-RT-000250'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-22792r409754_fix'
  tag 'documentable'
  tag legacy: ['SV-110995', 'V-101891']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
