control 'SV-221008' do
  title 'The Cisco perimeter switch must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most switches, internal information flow control is a product of system design.'
  desc 'check', 'Review the switch configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. In the example below, the switch is peering BGP with DISN. ICMP echo and echo-reply packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound to the NIPRNet host-facing web server (x.12.1.22).

interface GigabitEthernet0/1
 description Link to DISN
 ip address x.12.1.10 255.255.255.0
 ip access-group FILTER_PERIMETER in
…
…
…
ip access-list extended FILTER_PERIMETER
 permit tcp any any established
 permit tcp host x.12.1.9 host x.12.1.10 eq bgp
 permit tcp host x.12.1.9 eq bgp host x.12.1.10
 permit icmp host x.12.1.9 host x.12.1.10 echo
 permit icmp host x.12.1.9 host x.12.1.10 echo-reply
 permit tcp any host x.12.1.22 eq www
 deny ip any any log-input

If the switch is not configured to enforce approved authorizations for controlling the flow of information between interconnected networks, this is a finding.'
  desc 'fix', 'Step 1: Configure an ACL to allow or deny traffic as shown in the example below:

SW1(config)#ip access-list extended FILTER_PERIMETER
SW1(config-ext-nacl)#permit tcp any any established
SW1(config-ext-nacl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp
SW1(config-ext-nacl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10
SW1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo
SW1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply
SW1(config-ext-nacl)#permit tcp any host x.12.1.22 eq www
SW1(config-ext-nacl)#deny ip any any log-input
SW1(config-ext-nacl)#exit

Step 2: Apply the ACL inbound on all external interfaces.

R2(config)#int g0/0
SW1(config-if)#ip access-group FILTER_PERIMETER in'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22723r408818_chk'
  tag severity: 'medium'
  tag gid: 'V-221008'
  tag rid: 'SV-221008r622190_rule'
  tag stig_id: 'CISC-RT-000250'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-22712r408819_fix'
  tag 'documentable'
  tag legacy: ['SV-110837', 'V-101733']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
