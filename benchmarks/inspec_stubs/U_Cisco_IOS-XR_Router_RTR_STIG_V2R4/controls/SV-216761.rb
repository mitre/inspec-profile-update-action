control 'SV-216761' do
  title 'The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that an inbound ACL is configured on all external interfaces as shown in the example below.
interface GigabitEthernet0/0/0/1
 ipv4 address x.11.1.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

If the router is not configured to filter traffic entering the network at all external interfaces in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to use an inbound ACL on all external interfaces as shown in the example below.

RP/0/0/CPU0:R3(config)#int g0/0/0/1  
RP/0/0/CPU0:R3(config-if)#ipv4 access-group EXTERNAL_ACL_INBOUND in
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17993r288669_chk'
  tag severity: 'medium'
  tag gid: 'V-216761'
  tag rid: 'SV-216761r531087_rule'
  tag stig_id: 'CISC-RT-000330'
  tag gtitle: 'SRG-NET-000205-RTR-000004'
  tag fix_id: 'F-17991r288670_fix'
  tag 'documentable'
  tag legacy: ['SV-105867', 'V-96729']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
