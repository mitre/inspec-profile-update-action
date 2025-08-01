control 'SV-221080' do
  title 'The Cisco switch must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the switch—the key component used to build forwarding paths and is instrumental with all network management functions. Hence, any disruption or DoS attack to the route processor can result in mission critical network outages.'
  desc 'check', 'Review the external and internal ACLs to verify that the switch is configured to only allow specific management and control plane traffic from specific sources destined to itself.

Step 1: Verify ACLs has been configured as shown in the example below that matches expected control plane and management plane traffic. With the exception of ICMP, all other traffic destined to the switch should be dropped.

ip access-list EXTERNAL_ACL
 10 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 20 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 30 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
 40 permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
 50 deny ip any x.11.1.1/32 log 
 60 permit … 
 …
 …
 …
90 deny ip any any log 

ip access-list INTERNAL_ACL
 10 permit icmp any any 
 20 permit ospf 10.1.12.1/32 10.1.12.2/32 
 30 permit tcp 10.2.1.0/24 10.1.12.2/32 eq 22 
 40 permit tcp 10.2.1.0/24 10.1.12.2/32 eq tacacs 
 50 permit udp 10.2.1.0/24 10.1.12.2/32 eq snmp 
 60 permit udp 10.2.1.0/24 10.1.12.2/32 eq ntp 
 70 deny ip any 10.1.12.2/32 log 
 80 permit ….
90 deny ip any any log

Note: For the internal ACL example, all switches within the hypothetical network (10.1.0.0/16) have been configured to use the loopback address to source all management traffic (not shown); hence, the loopbacks are the only allowable destination address for management traffic. In addition, all management traffic destined to the switch must originate from the management network (10.2.1.0/24). With the exception of link-local control plane traffic and ICMP, all other traffic destined to any physical interface address will be dropped.

Step 2: Verify that the ACL has been applied to the appropriate interface as shown in the example below:

interface Ethernet1/2
 no switchport
 ip access-group EXTERNAL_ACL in
 ip address x.11.1.2 255.255.255.254
interface Ethernet1/3
 no switchport
 ip access-group INTERNAL_ACL in
 ip address 10.1.12.2 255.255.255.0

If the switch is not configured to restrict traffic destined to itself, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL for any external interfaces as shown in the example below:

SW1(config)# ip access-list EXTERNAL_ACL
SW1(config-acl)# permit tcp host x.11.1.1 eq bgp host x.11.1.2 
SW1(config-acl)# permit tcp host x.11.1.1 host x.11.1.2 eq bgp
SW1(config-acl)# permit icmp host x.11.1.1 host x.11.1.2 echo
SW1(config-acl)# permit icmp host x.11.1.1 host x.11.1.2 echo-reply
SW1(config-acl)# deny ip any host x.11.1.1 log
SW1(config-acl)# permit …
…
…
…
SW1(config-acl)# deny ip any any log

Configure the ACL for any external interfaces as shown in the example below:

SW1(config)# ip access-list INTERNAL_ACL
SW1(config-acl)# permit ospf host 10.1.12.1 host 10.1.12.2
SW1(config-acl)# permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq 22
SW1(config-acl)# permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq tacacs
SW1(config-acl)# permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq snmp
SW1(config-acl)# permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp
SW1(config-acl)# deny ip any host 10.1.12.2 log
SW1(config-acl)# permit …
…
…
…
SW1(config-acl)# permit ip any any log
SW1(config-acl)# exit

Note: best practice is to configure the ACL statements relative to traffic destined to the switch first followed by ACL statements for transit traffic.

Step 2: Apply the ACLs to the appropriate interface as shown in the example below:

SW1(config)# int e1/2
SW1(config-if)# ip access-group EXTERNAL_ACL in
SW1(config)# int e1/3
SW1(config-if)# ip access-group INTERNAL_ACL in'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22795r409729_chk'
  tag severity: 'high'
  tag gid: 'V-221080'
  tag rid: 'SV-221080r622190_rule'
  tag stig_id: 'CISC-RT-000130'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-22784r409730_fix'
  tag 'documentable'
  tag legacy: ['SV-110979', 'V-101875']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
