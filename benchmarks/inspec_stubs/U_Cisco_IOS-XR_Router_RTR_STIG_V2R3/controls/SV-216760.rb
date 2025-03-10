control 'SV-216760' do
  title 'The Cisco perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.'
  desc 'Vulnerability assessments must be reviewed by the System Administrator, and protocols must be approved by the Information Assurance (IA) staff before entering the enclave.

Access control lists (ACLs) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to reach a potential target within the security domain. The lists provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but that are stopped by an ACL will allow network administrators to broaden their protective ring and more tightly define the scope of operation.

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked would be satisfied.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that the ingress ACL is in accordance with DoD 8551.1.

Step 1: Verify that an inbound ACL is configured on all external interfaces.

interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

Step 2. Review the inbound ACL to verify that it is filtering traffic in accordance with DoD 8551.1.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.11.1.1 eq bgp host x.11.1.2
 20 permit tcp host x.11.1.1 host x.11.1.2 eq bgp
 30 permit icmp host x.11.1.1 host x.11.1.2 echo
 40 permit icmp host x.11.1.1 host x.11.1.2 echo-reply
 50 deny ipv4 any host x.11.1.1 log 
 60 permit tcp any host x.12.1.22 eq www
 70 permit tcp any any established
 …
 …    < must be in accordance with DoD Instruction 8551.1>
 …
160 deny ipv4 any any log-input 
 
If the router does not filter traffic in accordance with the guidelines contained in DoD 8551.1, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to use an inbound ACL on all external interfaces as shown in the example below to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1.

RP/0/0/CPU0:R3(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 eq bgp host x.11.1.2
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp host x.11.1.1 host x.11.1.2 eq bgp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp host x.11.1.1 host x.11.1.2 echo-reply
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any host x.11.1.1 log-input 
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any host x.12.1.22 eq www
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp any any established
…
…    < must be in accordance with DoD Instruction 8551.1>
…
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ip any any log-input 
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

Step 2: Apply the ACL inbound on all applicable interfaces.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17992r288666_chk'
  tag severity: 'medium'
  tag gid: 'V-216760'
  tag rid: 'SV-216760r531087_rule'
  tag stig_id: 'CISC-RT-000320'
  tag gtitle: 'SRG-NET-000205-RTR-000003'
  tag fix_id: 'F-17990r288667_fix'
  tag 'documentable'
  tag legacy: ['SV-105865', 'V-96727']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
