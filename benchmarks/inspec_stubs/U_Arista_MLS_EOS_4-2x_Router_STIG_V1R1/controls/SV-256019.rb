control 'SV-256019' do
  title 'The Arista perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to verify the egress ACL is bound to the internal interface in an inbound direction.

Step 1: To verify the egress ACL is bound to the internal interface in an inbound direction, execute the command "sh ip access-list".

ip access-list WAN_OUT
   10 permit tcp any host 180.20.10.1 eq ssh telnet
   20 permit ip any 190.16.10.0/24 
   30 permit udp any 67.56.10.2 eq bootps snmp
   40 deny tcp any 208.73.210.0 0.0.1.255
   50 deny udp any 208.73.210.0 0.0.1.255
   60 deny icmp any any
   70 permit ip any any

Step 2: To verify the ACL is applied inbound on all external interfaces, execute the command "sh run int Eth YY".

interface ethernet 8
  ip access-group WAN_OUT in

If the Arista router is not configured to filter traffic leaving the network at the internal interface in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Step 1: Configure an egress ACL bound to the internal interface in an inbound direction to filter traffic leaving the network.

Leaf2(config)#ip access-list WAN_OUT
Leaf2(config-acl-WAN_OUT)#10 permit tcp any host 180.20.10.1 eq ssh telnet
Leaf2(config-acl-WAN_OUT)#20 permit ip any 190.16.10.0/24 
Leaf2(config-acl-WAN_OUT)#30 permit udp any host 67.56.10.2 eq bootps snmp 
Leaf2(config-acl-WAN_OUT)#40 deny tcp any 208.73.210.0 0.0.1.255
Leaf2(config-acl-WAN_OUT)#50 deny udp any 208.73.210.0 0.0.1.255
Leaf2(config-acl-WAN_OUT)#60 deny icmp any any
Leaf2(config-acl-WAN_OUT)#70 permit ip any any

Step 2: Apply the ACL inbound on all external interfaces.

Leaf2(config)#interface ethernet 8
Leaf2(config-if-Et8)#  ip access-group WAN_OUT in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59695r882397_chk'
  tag severity: 'medium'
  tag gid: 'V-256019'
  tag rid: 'SV-256019r882399_rule'
  tag stig_id: 'ARST-RT-000380'
  tag gtitle: 'SRG-NET-000205-RTR-000005'
  tag fix_id: 'F-59638r882398_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
