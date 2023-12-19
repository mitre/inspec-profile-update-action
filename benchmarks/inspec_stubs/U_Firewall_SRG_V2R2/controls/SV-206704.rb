control 'SV-206704' do
  title 'The firewall must apply egress filters to traffic that is outbound from the network through any internal interface.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks or packets from networks destined to unauthorized networks may not be detected and prevented.

Access control policies and access control lists implemented on devices, such as firewalls, that control the flow of network traffic ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet) must be kept separated.

This requirement addresses the binding of the egress filter to the interface/zone rather than the content of the egress filter.'
  desc 'check', 'Obtain and review the list of authorized sources and destinations. This is usually part of the System Design Specification, Accreditation or Authorization Package, ports, protocols, and services documentation, and Ports, Protocols, and Services Management (PPSM) database.

If the list of authorized sources and destinations is not available, this is a finding. 

Review the firewall configuration for each of the configured outbound zones and interfaces.

Verify a security policy is applied to each outbound zone/interface, including the management interface.

If an egress filter is not configured for each active outbound zone or interface, this is a finding.'
  desc 'fix', 'Configure a security policy to each outbound zone and/or interface to implement continuous filtering of outbound traffic.

Apply security policy zones/interfaces (including the management interface) through which outbound traffic flows to untrusted external networks or subnetworks.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6961r297891_chk'
  tag severity: 'medium'
  tag gid: 'V-206704'
  tag rid: 'SV-206704r604133_rule'
  tag stig_id: 'SRG-NET-000364-FW-000032'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-6961r297892_fix'
  tag 'documentable'
  tag legacy: ['SV-94177', 'V-79471']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
