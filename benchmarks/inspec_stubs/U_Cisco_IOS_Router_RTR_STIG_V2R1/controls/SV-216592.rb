control 'SV-216592' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC).'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. It is only applicable if the OOBM gateway router is not a dedicated device to the OOBM backbone.

Verify that traffic destined to itself is only sourced by the OOBM or the NOC. In the example below, the OOBM backbone network is 10.11.1.0/24, the NOC address spaces is 10.12.1.0/24, and the OOBM LAN address space at remote site connecting to the managed network is 10.13.1.0/24.

Step 1: Note the inbound ACL applied to the OOBM interfaces.

interface GigabitEthernet0/2
 description OOB link to NOC
 ip address 10.11.1.8 255.255.255.0
 ip access-group TRAFFIC_FROM_NOC in
!
interface GigabitEthernet0/3
 description link to OOBM LAN access switch
 ip address 10.13.1.1 255.255.255.0
 ip access-group TRAFFIC_TO_NOC in

Step 2: Review the inbound ACL bound to any OOB interface connecting to the OOBM backbone and verify traffic destined to itself is only from the OOBM or NOC address space.

ip access-list extended TRAFFIC_FROM_NOC
 permit ip 10.11.1.0 0.255.255.255 host 10.11.1.8
 permit ip 10.12.1.0 0.255.255.255 host 10.11.1.8
 permit ip 10.11.1.0 0.255.255.255 host 10.13.1.1
 permit ip 10.12.1.0 0.255.255.255 host 10.13.1.1
 deny   ip any host 10.11.1.8 log-input
 deny   ip any host 10.13.1.1 log-input
 permit ip 10.11.1.0 0.0.0.255 10.13.1.0 0.0.0.255
 permit ip 10.12.1.0 0.0.0.255 10.13.1.0 0.0.0.255
 deny   ip any any log-input

Step 3: Review the inbound ACL bound to any OOBM LAN interfaces and verify traffic destined to itself is from the OOBM LAN address space.

ip access-list extended TRAFFIC_TO_NOC
 permit ip 10.13.1.0 0.255.255.255 host 10.13.1.1
 permit ip 10.13.1.0 0.255.255.255 host 10.11.1.8
 deny   ip any host 10.13.1.1 log-input
 deny   ip any host 10.11.1.8 log-input
 permit ip 10.13.1.0 0.255.255.255 10.11.1.0 0.0.0.255
 permit ip 10.13.1.0 0.255.255.255 10.12.1.0 0.0.0.255
 deny   ip any any log-input

If the router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone. It is only applicable if the OOBM gateway router is not a dedicated device to the OOBM backbone.

Step 1: Configure the ACL to only allow traffic to the route processor from the OOBM backbone and the NOC.

R4(config)#ip access-list extended TRAFFIC_FROM_NOC
R4(config-ext-nacl)#permit ip 10.11.1.0 0.255.255.255 host 10.11.1.8
R4(config-ext-nacl)#permit ip 10.12.1.0 0.255.255.255 host 10.11.1.8
R4(config-ext-nacl)#permit ip 10.11.1.0 0.255.255.255 host 10.13.1.1
R4(config-ext-nacl)#permit ip 10.12.1.0 0.255.255.255 host 10.13.1.1
R4(config-ext-nacl)#deny ip any host 10.11.1.8 log-input
R4(config-ext-nacl)#deny ip any host 10.13.1.1 log-input
R4(config-ext-nacl)#permit ip 10.11.1.0 0.0.0.255 10.13.1.0 0.0.0.255
R4(config-ext-nacl)#permit ip 10.12.1.0 0.0.0.255 10.13.1.0 0.0.0.255
R4(config-ext-nacl)#deny ip any any log-input

 Step 2: Configure the ACL to only allow traffic to the route processor from the OOBM LAN.

R4(config)#ip access-list extended TRAFFIC_TO_NOC
R4(config-ext-nacl)#permit ip 10.13.1.0 0.255.255.255 host 10.13.1.1
R4(config-ext-nacl)#permit ip 10.13.1.0 0.255.255.255 host 10.11.1.8
R4(config-ext-nacl)#deny ip any host 10.13.1.1 log-input
R4(config-ext-nacl)#deny ip any host 10.11.1.8 log-input
R4(config-ext-nacl)#permit ip 10.13.1.0 0.255.255.255 10.11.1.0 0.0.0.255
R4(config-ext-nacl)#permit ip 10.13.1.0 0.255.255.255 10.12.1.0 0.0.0.255
R4(config-ext-nacl)#deny ip any any log-input
R4(config-ext-nacl)#exit

Step 3: Apply the ACLs configured above to the appropriate OOBM interfaces as shown in the example below.

R4(config)#int g0/2
R4(config-if)#ip access-group TRAFFIC_FROM_NOC in
R4(config)#int g0/3
R4(config-if)#ip access-group TRAFFIC_TO_NOC in
R4(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17827r287154_chk'
  tag severity: 'medium'
  tag gid: 'V-216592'
  tag rid: 'SV-216592r531085_rule'
  tag stig_id: 'CISC-RT-000440'
  tag gtitle: 'SRG-NET-000205-RTR-000011'
  tag fix_id: 'F-17823r287155_fix'
  tag 'documentable'
  tag legacy: ['V-96585', 'SV-105723']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
