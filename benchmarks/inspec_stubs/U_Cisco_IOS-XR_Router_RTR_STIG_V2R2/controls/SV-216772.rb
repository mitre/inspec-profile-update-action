control 'SV-216772' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC).'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. It is only applicable if the OOBM gateway router is not a dedicated device to the OOBM backbone.

Verify that traffic destined to itself is only sourced by the OOBM or the NOC. In the example below, the OOBM backbone network is 10.11.1.0/24, the NOC address spaces is 10.12.1.0/24, and the OOBM LAN address space at remote site connecting to the managed network is 10.13.1.0/24.

Step 1: Note the inbound ACL applied to the OOBM interfaces.

interface GigabitEthernet0/0/0/2
 description OOB link to NOC
 ip address 10.11.1.8 255.255.255.0
 ipv4 access-group TRAFFIC_FROM_NOC ingress
!
interface Giga GigabitEthernet0/0/0/3
 description link to OOBM LAN access switch
 ip address 10.13.1.1 255.255.255.0
 ipv4 access-group TRAFFIC_TO_NOC ingress

Step 2: Review the inbound ACL bound to any OOB interface connecting to the OOBM backbone and verify traffic destined to itself is only from the OOBM or NOC address space.

ipv4 access-list TRAFFIC_FROM_NOC
 10 permit ipv4 10.11.1.0 0.255.255.255 host 10.11.1.8
 20 permit ipv4 10.12.1.0 0.255.255.255 host 10.11.1.8
 30 permit ipv4 10.11.1.0 0.255.255.255 host 10.13.1.1
 40 permit ipv4 10.12.1.0 0.255.255.255 host 10.13.1.1
 50 deny ipv4 any host 10.11.1.8 log-input
 60 deny ipv4 any host 10.13.1.1 log-input
 70 permit ipv4 10.11.1.0 0.0.0.255 10.13.1.0 0.0.0.255
 80 permit ipv4 10.12.1.0 0.0.0.255 10.13.1.0 0.0.0.255
 90 deny ipv4 any any log-input

Step 3: Review the inbound ACL bound to any OOBM LAN interfaces and verify traffic destined to itself is from the OOBM LAN address space.

ipv4 access-list TRAFFIC_TO_NOC
 10 permit ipv4 10.13.1.0 0.255.255.255 host 10.13.1.1
 20 permit ipv4 10.13.1.0 0.255.255.255 host 10.11.1.8
 30 deny ipv4 any host 10.13.1.1 log-input
 40 deny ipv4 any host 10.11.1.8 log-input
 50 permit ipv4 10.13.1.0 0.255.255.255 10.11.1.0 0.0.0.255
 60 permit ipv4 10.13.1.0 0.255.255.255 10.12.1.0 0.0.0.255
 70 deny ipv4 any any log-input

If the router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone. It is only applicable if the OOBM gateway router is not a dedicated device to the OOBM backbone.

Step 1: Configure the ACL to only allow traffic to the route processor from the OOBM backbone and the NOC.

RP/0/0/CPU0:R2(config)#ipv4 access-list TRAFFIC_FROM_NOC
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.11.1.0 0.255.255.255 host 10.11.$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.12.1.0 0.255.255.255 host 10.11.$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.11.1.0 0.255.255.255 host 10.13.$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.12.1.0 0.255.255.255 host 10.13.$
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any host 10.11.1.8 log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any host 10.13.1.1 log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.11.1.0 0.0.0.255 10.13.1.0 0.0.0$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.12.1.0 0.0.0.255 10.13.1.0 0.0.0$
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#exit

Step 2: Configure the ACL to only allow traffic to the route processor from the OOBM LAN.

RP/0/0/CPU0:R2(config)#ipv4 access-list TRAFFIC_TO_NOC
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.13.1.0 0.255.255.255 host 10.13.$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.13.1.0 0.255.255.255 host 10.11.$
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any host 10.13.1.1 log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any host 10.11.1.8 log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.13.1.0 0.255.255.255 10.11.1.0 0$
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip 10.13.1.0 0.255.255.255 10.12.1.0 0$
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any any log-input
RP/0/0/CPU0:R2(config-ipv4-acl)#exit

Step 3: Apply the ACLs configured above to the appropriate OOBM interfaces as shown in the example below.

RP/0/0/CPU0:R2(config)#int g0/0/0/2
RP/0/0/CPU0:R2(config-if)#ipv4 access-group TRAFFIC_FROM_NOC in
RP/0/0/CPU0:R2(config)#int g0/0/0/3
RP/0/0/CPU0:R2(config-if)#access-group TRAFFIC_TO_NOC in
RP/0/0/CPU0:R2(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18004r288699_chk'
  tag severity: 'medium'
  tag gid: 'V-216772'
  tag rid: 'SV-216772r531087_rule'
  tag stig_id: 'CISC-RT-000440'
  tag gtitle: 'SRG-NET-000205-RTR-000011'
  tag fix_id: 'F-18002r288700_fix'
  tag 'documentable'
  tag legacy: ['SV-105889', 'V-96751']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
