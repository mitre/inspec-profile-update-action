control 'SV-216802' do
  title 'The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF loose mode to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', 'Review the router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

interface GigabitEthernet1/1/0/0
 ip address x.1.12.2 255.255.255.252
 ipv4 verify unicast source reachable-via any

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Configure uRPF loose mode on all CE-facing interfaces as shown in the example

RP/0/0/CPU0:R3(config)#int g1/1/0/0
RP/0/0/CPU0:R3(config-if)#ipv4 verify unicast source reachable-via any'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18034r288783_chk'
  tag severity: 'medium'
  tag gid: 'V-216802'
  tag rid: 'SV-216802r531087_rule'
  tag stig_id: 'CISC-RT-000740'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-18032r288784_fix'
  tag 'documentable'
  tag legacy: ['SV-105949', 'V-96811']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
