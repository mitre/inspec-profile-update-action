control 'SV-256022' do
  title 'The Arista router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF loose mode to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', 'Review the Arista router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

To verify the interface configuration uRPF loose mode is enabled on all CE-facing interfaces, execute the command "sh run int Eth YY".

interface Ethernet 3/17/1
ip address 10.10.22.1/30
ip verify unicast source reachable-via any

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Enable uRPF loose mode on all CE-facing interfaces.

Configure uRPF loose mode on all CE-facing interfaces.

router(config)#interface Ethernet 3/17/1
router(config-if-Et3/17/1)#ip verify unicast source reachable-via any
router(config-if-Et3/17/1)#end'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59698r882406_chk'
  tag severity: 'medium'
  tag gid: 'V-256022'
  tag rid: 'SV-256022r882408_rule'
  tag stig_id: 'ARST-RT-000410'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-59641r882407_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
