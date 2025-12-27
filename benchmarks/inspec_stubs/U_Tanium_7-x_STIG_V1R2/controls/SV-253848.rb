control 'SV-253848' do
  title 'Firewall rules must be configured on the Tanium Server for client-to-server communications.'
  desc "In addition to the client-to-server TCP communication that takes place over port 17472, Tanium Clients also communicate to other Tanium-managed computers over port 17472. Without proper firewall configurations, proper TCP communications may not take place as necessary for application functionality. The Tanium environment can perform hundreds or thousands of times faster than other security or systems management tools because the Tanium Clients communicate in secure, linearly controlled peer-to-peer rings. Because clients dynamically communicate with other nearby agents based on proximity and latency, rings tend to form automatically to match a customer's topology. For example, endpoints in California will form one ring while endpoints in Germany will form a separate ring.

For more information, refer to https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/network_ports.html."
  desc 'check', 'Note: This check is performed for the Tanium endpoints and must be validated against the enterprise firewall solution (e.g., Endpoint Security Solution Firewall, Microsoft Windows Defender Firewall setting, Microsoft Advance Threat Protection Firewall, etc.) policies applied to the endpoints.

1. Consult with the personnel who maintain the Enterprise Security Suite configuration for assistance.

2. Validate a rule exists within the firewall policies for managed clients for the following:

Port Needed: Tanium Clients or Zone Clients over TCP port 17472, bidirectionally.

If a host-based firewall rule does not exist to allow TCP port 17472, bidirectionally, this is a finding.

3. Consult with the boundary network firewall administrator and validate rules exist for the following:

Allow TCP traffic on port 17472 from any computer to be managed on a local area network to any other computer to be managed on the same local area network.

If a network firewall rule does not exist to allow TCP port 17472 from any managed computer to any other managed computer on the same local area network, this is a finding.'
  desc 'fix', '1. Consult with the personnel who maintain the Enterprise Security Suite to configure host-based and network firewall rules to allow the following:

Tanium Clients or Zone Clients over TCP port 17472, bidirectionally.

2. Consult with the boundary network firewall administrator to create a rule to allow the following:

TCP traffic on port 17472 from any computer to be managed on a local area network to any other computer to be managed on the same local area network.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57300r842570_chk'
  tag severity: 'medium'
  tag gid: 'V-253848'
  tag rid: 'SV-253848r842572_rule'
  tag stig_id: 'TANS-SV-000017'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-57251r842571_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
