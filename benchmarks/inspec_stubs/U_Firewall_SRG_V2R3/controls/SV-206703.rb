control 'SV-206703' do
  title 'The firewall must apply ingress filters to traffic that is inbound to the network through any active external interface.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic, ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet) must be kept separated.'
  desc 'check', 'Obtain and review the list of authorized sources and destinations. This is usually part of the System Design Specification, Accreditation or Authorization Package, ports, protocols, and services documentation, and Ports, Protocols, and Services Management (PPSM) database.

If the list of authorized sources and destinations is not available, this is a finding.

Review the firewall configuration for each of the configured inbound zones and interfaces.

Verify an ingress filter (e.g., Access Control List) is applied to each inbound zone/interface, including the management interface.

Verify ingress filters for the management interface to block all transit traffic (i.e., any traffic not destined to the firewall itself). Verify that traffic accessing the firewall originates from the Network Operations Center (NOC).

If an ingress filter is not configured for each active inbound zone or interface, this is a finding.'
  desc 'fix', 'Configure a security policy to each inbound zone and/or interface to implement continuous filtering of outbound traffic.

Apply security policy zones/interfaces through which inbound traffic flows from untrusted external networks or subnetworks. 

Configure the ingress filters for the management interface to block all transit traffic (i.e., any traffic not destined to the firewall itself) and so that traffic accessing the firewall originates from the NOC.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6960r297888_chk'
  tag severity: 'medium'
  tag gid: 'V-206703'
  tag rid: 'SV-206703r855865_rule'
  tag stig_id: 'SRG-NET-000364-FW-000031'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-6960r297889_fix'
  tag 'documentable'
  tag legacy: ['V-79469', 'SV-94175']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
