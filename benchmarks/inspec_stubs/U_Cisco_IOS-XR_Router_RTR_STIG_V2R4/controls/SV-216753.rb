control 'SV-216753' do
  title 'The Cisco perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Review the router configuration to verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. In the example below, the router is peering BGP with DISN. ICMP echo and echo-reply packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound to the NIPRNet host-facing web server (x.12.1.22).

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log 
 60 permit tcp any host x.12.1.22 eq www
 70 permit tcp any any established
 80 deny ipv4 any any log-input 
…
…
…
interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

If the router is not configured to enforce approved authorizations for controlling the flow of information between interconnected networks, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Configure an ACL to allow or deny traffic as shown in the example below.

RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any host x.11.1.1 log-input 
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any host x.12.1.22 eq www
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any any established
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log-input 
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

Step 2: Apply the ACL inbound on all external interfaces.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17985r288648_chk'
  tag severity: 'medium'
  tag gid: 'V-216753'
  tag rid: 'SV-216753r531087_rule'
  tag stig_id: 'CISC-RT-000250'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-17983r288649_fix'
  tag 'documentable'
  tag legacy: ['SV-105851', 'V-96713']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
