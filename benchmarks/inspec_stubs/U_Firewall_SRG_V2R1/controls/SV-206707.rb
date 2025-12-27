control 'SV-206707' do
  title 'The premise firewall (located behind the premise router) must block all outbound management traffic.'
  desc "The management network must still have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. 

Safeguards must be implemented to ensure that the management traffic does not leak past the managed network's premise equipment. If a firewall is located behind the premise router, all management traffic must be blocked at that point, with the exception of management traffic destined to premise equipment."
  desc 'check', 'Review the firewall configuration to verify that it is blocking all outbound management traffic.

If the firewall is not blocking management network from leaking to outside networks, this is a finding.'
  desc 'fix', 'With the exception of management traffic destined to perimeter equipment, configure a firewall located behind the premise router to block all outbound management traffic.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6964r297900_chk'
  tag severity: 'medium'
  tag gid: 'V-206707'
  tag rid: 'SV-206707r604133_rule'
  tag stig_id: 'SRG-NET-000364-FW-000035'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-6964r297901_fix'
  tag 'documentable'
  tag legacy: ['SV-94183', 'V-79477']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
