control 'SV-254905' do
  title 'Firewall rules must be configured on the Tanium Endpoints for Client-to-Server communications.'
  desc 'In addition to the client-to-server TCP communication that takes place over port 17472, Tanium Clients also communicate to other Tanium-managed computers over port 17472. Without proper firewall configurations, proper TCP communications may not take place as necessary for application functionality. The Tanium environment can perform hundreds or thousands of times faster than other security or systems management tools because the Tanium Clients communicate in secure, linearly-controlled peer-to-peer rings. Because clients dynamically communicate with other nearby agents based on proximity and latency, rings tend to form automatically to match a customer’s topology—endpoints in California will form one ring while endpoints in Germany will form a separate ring.'
  desc 'check', 'Note: This check is performed for the Tanium Endpoints and must be validated against the enterprise firewall solution (e.g., Endpoint Security Solution Firewall, Microsoft Windows Defender Firewall setting, Microsoft Advance Threat Protection Firewall, etc.) policies applied to the Endpoints.

1. Consult with the personnel who maintain the Enterprise Security Suite configuration for assistance.

2. Validate a rule exists within the firewall policies for managed clients for the following:

2A. Port Needed: Tanium Clients or Zone Clients over TCP port 17472, bi-directionally.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, this is a finding.

3. Consult with the boundary network firewall administrator and validate rules exist for the following:

3A. Allow TCP traffic on port 17472 from any computer to be managed on a local area network to any other computer to be managed on the same local area network.

If a network firewall rule does not exist to allow TCP port 17472 from any managed computer to any other managed computer on the same local area network, this is a finding.'
  desc 'fix', '1. Consult with the personnel who maintain the Enterprise Security Suite to configure host-based and network firewall rules to allow the following:

1A. Tanium Clients or Zone Clients over TCP port 17472, bi-directionally.

2. Consult with the boundary network firewall administrator to create a rule to allow the following:

2A. TCP traffic on port 17472 from any computer to be managed on a local area network to any other computer to be managed on the same local area network.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58518r867613_chk'
  tag severity: 'medium'
  tag gid: 'V-254905'
  tag rid: 'SV-254905r867615_rule'
  tag stig_id: 'TANS-AP-000355'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-58462r867614_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
