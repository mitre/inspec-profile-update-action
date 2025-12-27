control 'SV-220456' do
  title 'The Cisco PE switch must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge switches must enable uRPF loose mode to guarantee that all packets received from a CE switch contain source addresses that are in the route table.'
  desc 'check', 'Review the switch configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

interface GigabitEthernet0/2
 no switchport
 ip address x.1.12.2 255.255.255.252
 ip access-group BLOCK_TO_CORE in
 ip verify unicast source reachable-via any

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Configure uRPF loose mode on all CE-facing interfaces as shown in the example below:

SW2(config)#int SW1(config)#int g0/2
SW2(config-if)#ip verify unicast source reachable-via any
SW2(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22171r508446_chk'
  tag severity: 'medium'
  tag gid: 'V-220456'
  tag rid: 'SV-220456r622190_rule'
  tag stig_id: 'CISC-RT-000740'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-22160r508447_fix'
  tag 'documentable'
  tag legacy: ['SV-110767', 'V-101663']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
