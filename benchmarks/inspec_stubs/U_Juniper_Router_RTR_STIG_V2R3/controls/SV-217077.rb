control 'SV-217077' do
  title 'The Juniper PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.'
  desc 'The uRPF feature is a defense against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF loose mode to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', 'Review the router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

interfaces {
    ge-0/1/0 {
        description "link to Customer 2";
        unit 0 {
            family inet {
                rpf-check {
                    mode loose;
                }
                address x.x.x.x/30;
            }
        }
    }

If uRPF loose mode is not enabled on all CE-facing interfaces, this is a finding.'
  desc 'fix', 'Configure uRPF loose mode on all CE-facing interfaces as shown in the example.

[edit interfaces ge-0/1/0 unit 0 family inet]
set rpf-check mode loose'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18306r297099_chk'
  tag severity: 'medium'
  tag gid: 'V-217077'
  tag rid: 'SV-217077r604135_rule'
  tag stig_id: 'JUNI-RT-000720'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-18304r297100_fix'
  tag 'documentable'
  tag legacy: ['SV-101145', 'V-90935']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
