control 'SV-216581' do
  title 'The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that an inbound ACL is configured on all external interfaces as shown in the example below.

interface GigabitEthernet0/2
 ip address x.11.1.2 255.255.255.254
 ip access-group EXTERNAL_ACL_INBOUND in

If the router is not configured to filter traffic entering the network at all external interfaces in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to use an inbound ACL on all external interfaces as shown in the example below.

R1(config)#int g0/2
R1(config-if)#ip access-group EXTERNAL_ACL_INBOUND in'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17816r287124_chk'
  tag severity: 'medium'
  tag gid: 'V-216581'
  tag rid: 'SV-216581r531085_rule'
  tag stig_id: 'CISC-RT-000330'
  tag gtitle: 'SRG-NET-000205-RTR-000004'
  tag fix_id: 'F-17812r287125_fix'
  tag 'documentable'
  tag legacy: ['SV-105701', 'V-96563']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
