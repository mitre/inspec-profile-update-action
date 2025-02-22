control 'SV-221013' do
  title 'The Cisco perimeter switch must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of switches makes use of access lists for restricting access to services on the switch itself as well as for filtering traffic passing through the switch. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The switch can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'Review the switch configuration to verify that an inbound ACL is configured on all external interfaces as shown in the example below:

interface GigabitEthernet0/2
 ip address x.11.1.2 255.255.255.254
 ip access-group EXTERNAL_ACL_INBOUND in

If the switch is not configured to filter traffic entering the network at all external interfaces in an inbound direction, this is a finding.'
  desc 'fix', 'Configure the switch to use an inbound ACL on all external interfaces as shown in the example below:

SW1(config)#int g0/2
SW1(config-if)#ip access-group EXTERNAL_ACL_INBOUND in'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22728r408833_chk'
  tag severity: 'medium'
  tag gid: 'V-221013'
  tag rid: 'SV-221013r622190_rule'
  tag stig_id: 'CISC-RT-000330'
  tag gtitle: 'SRG-NET-000205-RTR-000004'
  tag fix_id: 'F-22717r408834_fix'
  tag 'documentable'
  tag legacy: ['SV-110847', 'V-101743']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
