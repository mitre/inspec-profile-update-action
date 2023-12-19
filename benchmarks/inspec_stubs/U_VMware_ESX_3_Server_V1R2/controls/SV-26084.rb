control 'SV-26084' do
  title 'The system must use a reverse-path filter for IPv4 network traffic when possible.'
  desc 'Reverse-path filtering provides protection against spoofed source addresses by causing the system to discard packets that have source addresses for which the system has no route or if the route does not point towards the interface on which the packet arrived.  Reverse-path filtering should be used whenever possible.  Depending on the role of the system, reverse-path filtering may cause legitimate traffic to be discarded and, therefore, should be used in a more permissive mode or not at all.'
  desc 'check', "If the system is in an environment that does not allow the proper operation of reverse-path filtering, such as with asymmetric routing, this requirement is not applicable.

Consult vendor documentation to determine if a specific configuration setting exists to enable reverse-path filtering. If this feature exists and is not enabled, this is a finding.

If no specific feature is available, examine the system's local firewall configuration to determine if traffic with source addresses expected on one interface (including loopback interfaces) is blocked when received on another interface. If no such filtering is configured, this is a finding."
  desc 'fix', 'If the system has a reverse-path filter capability, enable this feature in accordance with vendor documentation. If the system does not have this capability, add local firewall rules to block traffic with loopback network source addresses from being received on interfaces other than the loopback. Additionally, if the system is multihomed and the attached networks are isolated or perform symmetric routing, add rules to block traffic with source addresses expected on one interface when received on another interface.

For example, consider a system with two network interfaces, one attached to an isolated management network with address 10.0.0.55/24 and the other attached to a production network with address 192.168.1.2/24 and a default route. Traffic with a source address on the 10.0.0.0/24 network must be the only traffic accepted on the management interface and must not be accepted on the production interface.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22420'
  tag rid: 'SV-26084r1_rule'
  tag stig_id: 'GEN003613'
  tag gtitle: 'GEN003613'
  tag fix_id: 'F-26276r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000027']
  tag nist: ['AC-4 (3)']
end
