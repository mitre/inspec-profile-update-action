control 'SV-216743' do
  title 'The Cisco router must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router—the key component used to build forwarding paths and is instrumental with all network management functions. Hence, any disruption or DoS attack to the route processor can result in mission critical network outages.'
  desc 'check', 'Review the external and internal ACLs to verify that the router is configured to only allow specific management and control plane traffic from specific sources destined to itself.

Step 1: Verify ACLs has been configured as shown in the example below that matches expected control plane and management plane traffic. With the exception of ICMP, all other traffic destined to the router should be dropped.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log 
 60 permit tcp any any established
 …
 …
 …
 140 deny ipv4 any any log 
!
ipv4 access-list INTERNAL_ACL_INBOUND
 10 permit icmp any any
 20 permit ospf host 10.1.12.1 host 10.1.12.2
 30 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ssh
 40 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq tacacs
 50 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2  eq snmp
 60 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp
 70 deny ipv4 any host 10.1.12.2 log 
 80 permit ipv4 any any  

Note: For the internal ACL example, all routers within the hypothetical network (10.1.0.0/16) have been configured to use the loopback address to source all management traffic (not shown); hence, the loopbacks are the only allowable destination address for management traffic. In addition, all management traffic destined to the router must originate from the management network (10.2.1.0/24). With the exception of link-local control plane traffic and ICMP, all other traffic destined to any physical interface address will be dropped.

Step 2: Verify that the ACL has been applied to the appropriate interface as shown in the example below.
 
interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress
!
interface GigabitEthernet0/0/0/2
 ipv4 address 10.1.12.2 255.255.255.0
 ipv4 access-group INTERNAL_ACL_INBOUND ingress
   
If the router is not configured to restrict traffic destined to itself, this is a finding.'
  desc 'fix', 'Configure the ACL for any external interfaces as shown in the example.

RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any host x.11.1.1 log 
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any any established
…
…
…
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log 
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

Configure the ACL for any external interfaces as shown in the example.

RP/0/0/CPU0:R3(config)#ipv4 access-list INTERNAL_ACL_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp any any
RP/0/0/CPU0:R3(config-ipv4-acl)#permit ospf host 10.1.12.1 host 10.1.12.2
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2eq 22
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2eq tacacs
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq snmp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp
RP/0/0/CPU0:R3(config-ipv4-acl)#deny  ip any host 10.1.12.2 log 
RP/0/0/CPU0:R3(config-ipv4-acl)#permit ip any any  
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

Note: best practice is to configure the ACL statements relative to traffic destined to the router first followed by ACL statements for transit traffic.

Step 2: Apply the ACLs to the appropriate interface as shown in the example below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#exit
RP/0/0/CPU0:R3(config)#int g0/0/0/2                     
RP/0/0/CPU0:R3(config-if)#ipv4 access-group INTERNAL_ACL_INBOUND in'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17975r288618_chk'
  tag severity: 'high'
  tag gid: 'V-216743'
  tag rid: 'SV-216743r531087_rule'
  tag stig_id: 'CISC-RT-000130'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-17973r288619_fix'
  tag 'documentable'
  tag legacy: ['SV-105831', 'V-96693']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
