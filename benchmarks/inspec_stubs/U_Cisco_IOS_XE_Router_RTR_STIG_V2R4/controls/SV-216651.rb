control 'SV-216651' do
  title 'The Cisco router must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router—the key component used to build forwarding paths and is instrumental with all network management functions. Hence, any disruption or denial of service (DoS) attack to the route processor can result in mission critical network outages.'
  desc 'check', 'Review the external and internal ACLs to verify that the router is configured to only allow specific management and control plane traffic from specific sources destined to itself.

Step 1: Verify ACLs has been configured as shown in the example below that matches expected control plane and management plane traffic. With the exception of  Internet Control Message Protocol (ICMP), all other traffic destined to the router should be dropped.

ip access-list extended EXTERNAL_ACL
 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 permit icmp host x.11.1.1 host x.11.1.2 echo
 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 deny   ip any host x.11.1.1 log-input
 permit …
 …
 …
 …
deny   ip any any log-input

ip access-list extended INTERNAL_ACL
 permit icmp any any
 permit ospf host 10.1.12.1 host 10.1.12.2
 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq 22
 permit tcp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq tacacs
 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq snmp
 permit udp 10.2.1.0 0.0.0.255 host 10.1.12.2 eq ntp
 deny   ip any host 10.1.12.2 log-input
 permit …
 …
 …
 …
 deny   ip any any log-input

Note: For the internal ACL example, all routers within the hypothetical network (10.1.0.0/16) have been configured to use the loopback address to source all management traffic (not shown); hence, the loopbacks are the only allowable destination address for management traffic. In addition, all management traffic destined to the router must originate from the management network (10.2.1.0/24). With the exception of link-local control plane traffic and ICMP, all other traffic destined to any physical interface address will be dropped.

Step 2: Verify that the ACL has been applied to the appropriate interface as shown in the example below:
 
interface GigabitEthernet0/2
 ip address x.11.1.2 255.255.255.254
 ip access-group EXTERNAL_ACL in
interface GigabitEthernet0/3
 ip address 10.1.12.2 255.255.255.0
 ip access-group INTERNAL_ACL in
   
If the router is not configured to restrict traffic destined to itself, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL for any external interfaces as shown in the example.

R1(config)#ip access-list extended EXTERNAL_ACL
R1(config-ext-nacl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2    
R1(config-ext-nacl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo
R1(config-ext-nacl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
R1(config-ext-nacl)#deny ip any host x.11.1.1 log-input
R1(config-ext-nacl)#permit …
…
…
…
R1(config-ext-nacl)#deny ip any any log-input

Step 2: Configure the ACL for any external interfaces as shown in the example.

R1(config)#ip access-list extended INTERNAL_ACL
R1(config-ext-nacl)#permit ospf host 10.1.12.1 host 10.1.12.2
R1(config-ext-nacl)#permit tcp 10.2.1.0 0.0.0.255  host 10.1.12.2 eq 22
R1(config-ext-nacl)#permit tcp 10.2.1.0 0.0.0.255  host 10.1.12.2 eq tacacs
R1(config-ext-nacl)#permit udp 10.2.1.0 0.0.0.255  host 10.1.12.2 eq snmp
R1(config-ext-nacl)#permit udp 10.2.1.0 0.0.0.255  host 10.1.12.2 eq ntp
R1(config-ext-nacl)#deny ip any host 10.1.12.2 log-input
R1(config-ext-nacl)#permit …
…
…
…
R1(config-ext-nacl)#permit ip any any log-input
R1(config-ext-nacl)#exit

Note: best practice is to configure the ACL statements relative to traffic destined to the router first followed by ACL statements for transit traffic.

Step 3: Apply the ACLs to the appropriate interface as shown in the example below:

R1(config)#int g0/2
R1(config-if)#ip access-group EXTERNAL_ACL in
R1(config)#int g0/3
R1(config-if)#ip access-group INTERNAL_ACL in'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17884r287910_chk'
  tag severity: 'high'
  tag gid: 'V-216651'
  tag rid: 'SV-216651r531086_rule'
  tag stig_id: 'CISC-RT-000130'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-17882r287911_fix'
  tag 'documentable'
  tag legacy: ['SV-106013', 'V-96875']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
