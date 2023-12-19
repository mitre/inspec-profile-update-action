control 'SV-216573' do
  title 'The Cisco perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Review the router configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. In the example below, the router is peering BGP with DISN. ICMP echo and echo-reply packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound to the NIPRNet host-facing web server (x.12.1.22).

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
 deny   ip any any log-input

If the router is not configured to enforce approved authorizations for controlling the flow of information between interconnected networks, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Configure an ACL to allow or deny traffic as shown in the example below.

R1(config)#ip access-list extended FILTER_PERIMETER
R1(config-ext-nacl)#permit tcp any any established
R1(config-ext-nacl)#permit tcp host x.12.1.9 host x.12.1.10 eq bgp
R1(config-ext-nacl)#permit tcp host x.12.1.9 eq bgp host x.12.1.10
R1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo
R1(config-ext-nacl)#permit icmp host x.12.1.9 host x.12.1.10 echo-reply
R1(config-ext-nacl)#permit tcp any host x.12.1.22 eq www
R1(config-ext-nacl)#deny ip any any log-input
R1(config-ext-nacl)#exit

Step 2: Apply the ACL inbound on all external interfaces.

R2(config)#int g0/0
R1(config-if)#ip access-group  FILTER_PERIMETER in'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17808r287103_chk'
  tag severity: 'medium'
  tag gid: 'V-216573'
  tag rid: 'SV-216573r531085_rule'
  tag stig_id: 'CISC-RT-000250'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-17804r287104_fix'
  tag 'documentable'
  tag legacy: ['SV-105685', 'V-96547']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
