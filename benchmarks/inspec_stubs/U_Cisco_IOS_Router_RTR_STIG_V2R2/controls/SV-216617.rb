control 'SV-216617' do
  title 'The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF loose mode to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', 'Review the router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

interface GigabitEthernet0/2
 ip address x.1.12.2 255.255.255.252
 ip access-group BLOCK_TO_CORE in
 ip verify unicast source reachable-via any

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Configure uRPF loose mode on all CE-facing interfaces as shown in the example below.

R2(config)#int R4(config)#int g0/2
R2(config-if)#ip verify unicast source reachable-via any
R2(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17852r287223_chk'
  tag severity: 'medium'
  tag gid: 'V-216617'
  tag rid: 'SV-216617r531085_rule'
  tag stig_id: 'CISC-RT-000740'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-17848r287224_fix'
  tag 'documentable'
  tag legacy: ['SV-105773', 'V-96635']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
