control 'SV-221094' do
  title 'The Cisco perimeter switch must be configured to filter egress traffic at the internal interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of switches makes use of access lists for restricting access to services on the switch itself as well as for filtering traffic passing through the switch. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The switch can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'Review the switch configuration to verify that the egress ACL is bound to the internal interface in an inbound direction.

interface Ethernet2/4
 description downstream link to LAN
 no switchport
 ip access-group EGRESS_FILTER in
 ip address 10.1.12.1/24

If the switch is not configured to filter traffic leaving the network at the internal interface in an inbound direction, this is a finding.'
  desc 'fix', 'Configure the switch to use an inbound ACL on all internal interfaces as shown in the example below:

SW1(config)# int e2/4
SW1(config-if)# ip access-group EGRESS_FILTER in
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22809r409771_chk'
  tag severity: 'medium'
  tag gid: 'V-221094'
  tag rid: 'SV-221094r622190_rule'
  tag stig_id: 'CISC-RT-000340'
  tag gtitle: 'SRG-NET-000205-RTR-000005'
  tag fix_id: 'F-22798r409772_fix'
  tag 'documentable'
  tag legacy: ['SV-111007', 'V-101903']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
