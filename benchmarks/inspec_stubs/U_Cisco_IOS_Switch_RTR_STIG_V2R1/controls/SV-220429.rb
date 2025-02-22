control 'SV-220429' do
  title 'The Cisco switch must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the switch. This is the key component used to build forwarding paths and is instrumental with all network management functions. Hence, any disruption or denial-of-service (DoS) attack to the route processor can result in mission-critical network outages.'
  desc 'check', 'Review the external and internal access control lists (ACLs) to verify that the switch is configured to only allow specific management and control plane traffic from specific sources destined to itself. 

Step 1: Verify that ACLs have been configured as shown in the example below that matches expected control plane and management plane traffic. With the exception of Internet Control Message Protocol (ICMP), all other traffic destined to the switch should be dropped. 

ip access-list extended EXTERNAL_ACL 
 permit icmp host x.11.1.1 host x.11.1.2 echo 
 permit icmp host x.11.1.1 host x.11.1.2 echo-reply 
 deny ip any host x.11.1.1 log-input 
 permit … 
 … 
 … 
 … 
deny ip any any log-input 

ip access-list extended INTERNAL_ACL 
 permit icmp any any 
 permit ospf host 10.1.12.1 host 10.1.12.2 
 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq 22 
 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq tacacs 
 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq snmp 
 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp 
 deny ip any host 10.1.12.2 log-input 
 permit … 
 … 
 … 
 … 
deny ip any any log-input 

Note: For the internal ACL example, all switches within the hypothetical network (10.1.0.0/16) have been configured to use the loopback address to source all management traffic (not shown); hence, the loopbacks are the only allowable destination address for management traffic. In addition, all management traffic destined to the switch must originate from the management network (10.2.1.0/24). With the exception of link-local control plane traffic and ICMP, all other traffic destined to any physical interface address will be dropped. 

Step 2: Verify that the ACL has been applied to the appropriate interface as shown in the example below: 

interface GigabitEthernet0/2 
 no switchport 
 ip address x.11.1.2 255.255.255.254 
 ip access-group EXTERNAL_ACL in 
interface GigabitEthernet0/3 
 no switchport 
 ip address 10.1.12.2 255.255.255.0 
 ip access-group INTERNAL_ACL in 

If the switch is not configured to restrict traffic destined to itself, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL for any external interfaces as shown in the example below: 

SW1(config)#ip access-list extended EXTERNAL_ACL 
SW1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo 
SW1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply 
SW1(config-ext-nacl)#deny ip any host x.11.1.1 log-input 
SW1(config-ext-nacl)#permit … 
… 
… 
… 
SW1(config-ext-nacl)#deny ip any any log-input 

Step 2: Configure the ACL for any external interfaces as shown in the example below: 

SW1(config)#ip access-list extended INTERNAL_ACL 
SW1(config-ext-nacl)#permit ospf host 10.1.12.1 host 10.1.12.2 
SW1(config-ext-nacl)#permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq 22 
SW1(config-ext-nacl)#permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq tacacs 
SW1(config-ext-nacl)#permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq snmp 
SW1(config-ext-nacl)#permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp 
SW1(config-ext-nacl)#deny ip any host 10.1.12.2 log-input 
SW1(config-ext-nacl)#permit … 
… 
… 
… 
SW1(config-ext-nacl)#permit ip any any log-input 
SW1(config-ext-nacl)#exit 

Note: Best practice is to configure the ACL statements relative to traffic destined to the switch first followed by ACL statements for transit traffic. 

Step 3: Apply the ACLs to the appropriate interface as shown in the example below: 

SW1(config)#int g0/2 
SW1(config-if)#ip access-group EXTERNAL_ACL in 
SW1(config)#int g0/3 
SW1(config-if)#ip access-group INTERNAL_ACL in'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22144r508372_chk'
  tag severity: 'high'
  tag gid: 'V-220429'
  tag rid: 'SV-220429r622190_rule'
  tag stig_id: 'CISC-RT-000130'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-22133r508373_fix'
  tag 'documentable'
  tag legacy: ['SV-110705', 'V-101601']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
