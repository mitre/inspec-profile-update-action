control 'SV-216762' do
  title 'The Cisco perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that the egress ACL is bound to the internal interface in an inbound direction.

interface GigabitEthernet0/0/0/1
 description downstream link to LAN
 ipv4 address 10.1.34.3 255.255.255.0
 ipv4 access-group EGRESS_FILTER ingress

If the router is not configured to filter traffic leaving the network at the internal interface in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to use an inbound ACL on all internal interfaces as shown in the example below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EGRESS_FILTER in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17994r288672_chk'
  tag severity: 'medium'
  tag gid: 'V-216762'
  tag rid: 'SV-216762r531087_rule'
  tag stig_id: 'CISC-RT-000340'
  tag gtitle: 'SRG-NET-000205-RTR-000005'
  tag fix_id: 'F-17992r288673_fix'
  tag 'documentable'
  tag legacy: ['SV-105869', 'V-96731']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
