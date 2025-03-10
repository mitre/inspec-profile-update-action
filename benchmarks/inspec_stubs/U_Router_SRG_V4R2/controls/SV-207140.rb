control 'SV-207140' do
  title 'The PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces..'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF loose mode to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', 'Review the router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Enable uRPF loose mode on all CE-facing interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7401r382358_chk'
  tag severity: 'medium'
  tag gid: 'V-207140'
  tag rid: 'SV-207140r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000008'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7401r382359_fix'
  tag 'documentable'
  tag legacy: ['V-78315', 'SV-93021']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
