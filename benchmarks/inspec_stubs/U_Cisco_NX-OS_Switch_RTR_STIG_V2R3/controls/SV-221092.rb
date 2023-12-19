control 'SV-221092' do
  title 'The Cisco perimeter switch must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.'
  desc 'Vulnerability assessments must be reviewed by the System Administrator, and protocols must be approved by the Information Assurance (IA) staff before entering the enclave.

ACLs are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to reach a potential target within the security domain. The lists provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network that are stopped by an ACL will allow network administrators to broaden their protective ring and more tightly define the scope of operation.

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked would be satisfied.'
  desc 'check', 'Review the switch configuration to verify that the ingress ACL is in accordance with DoD 8551.1.

Step 1: Verify that an inbound ACL is configured on all external interfaces.

interface Ethernet2/2
 description link to DISN
 no switchport
 ip access-group EXTERNAL_ACL in

Step 2. Review the inbound ACL to verify that it is filtering traffic in accordance with DoD 8551.1.

ip access-list EXTERNAL_ACL
 10 permit tcp any any established 
 20 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 30 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 40 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
 50 permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
 60 permit tcp any x.11.2.3/32 eq www 
 70 permit udp x.12.1.9/32 x.12.1.21/32 eq ntp
…
 … < must be in accordance with DoD Instruction 8551.1>
…
140 deny ip any any log

If the switch does not filter traffic in accordance with the guidelines contained in DoD 8551, this is a finding.'
  desc 'fix', 'Configure the switch to use an inbound ACL on all external interfaces as shown in the example below to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1.

SW2(config)# ip access-list EXTERNAL_ACL
SW2(config-acl)# permit tcp any any established
SW2(config-acl)# permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
SW2(config-acl)# permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
SW2(config-acl)# permit icmp x.11.1.1/32 x.11.1.2/32 echo 
SW2(config-acl)# permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
SW2(config-acl)# permit tcp any x.11.2.3/32 eq www 
…
… < must be in accordance with DoD Instruction 8551.1>
…
SW2(config-acl)# deny ip any any log
SW2(config-acl)# exit
SW1(config)#int e2/2
SW1(config-if)# ip access-group EXTERNAL_ACL in
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22807r409765_chk'
  tag severity: 'medium'
  tag gid: 'V-221092'
  tag rid: 'SV-221092r622190_rule'
  tag stig_id: 'CISC-RT-000320'
  tag gtitle: 'SRG-NET-000205-RTR-000003'
  tag fix_id: 'F-22796r409766_fix'
  tag 'documentable'
  tag legacy: ['SV-111003', 'V-101899']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
