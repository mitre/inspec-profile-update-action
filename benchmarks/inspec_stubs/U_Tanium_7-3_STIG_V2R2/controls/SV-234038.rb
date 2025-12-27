control 'SV-234038' do
  title 'Firewall rules must be configured on the Tanium Endpoints for Client-to-Server communications.'
  desc "In addition to the client-to-server TCP communication that takes place over port 17472, Tanium Clients also communicate to other Tanium-managed computers over port 17472. The Tanium environment can perform hundreds or thousands of times faster than other security or systems management tools because the Tanium Clients communicate in secure, linearly-controlled peer-to-peer rings. Because clients dynamically communicate with other nearby agents based on proximity and latency, rings tend to form automatically to match a customer's topology--endpoints in California will form one ring while endpoints in Germany will form a separate ring.

https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html."
  desc 'check', 'Note: This check is performed for the Tanium Endpoints and must be validated against the HBSS desktop firewall policy applied to the Endpoints.

Consult with the HBSS administration for assistance.

Validate a rule exists within the HBSS HIPS firewall policies for managed clients for the following:

Port Needed: Tanium Clients or Zone Clients over TCP port 17472, bi-directionally.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:

Allow TCP traffic on port 17472 from any computer to be managed on a local area network to any other computer to be managed on the same local area network.

If a network firewall rule does not exist to allow TCP port 17472 from any managed computer to any other managed computer on the same local area network, this is a finding.'
  desc 'fix', 'Configure host-based and network firewall rules as required.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37223r610614_chk'
  tag severity: 'medium'
  tag gid: 'V-234038'
  tag rid: 'SV-234038r612749_rule'
  tag stig_id: 'TANS-CL-000004'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-37188r610615_fix'
  tag 'documentable'
  tag legacy: ['SV-102149', 'V-92047']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
