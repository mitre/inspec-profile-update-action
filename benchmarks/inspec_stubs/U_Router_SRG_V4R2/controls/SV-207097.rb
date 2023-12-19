control 'SV-207097' do
  title 'The router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that access control lists (ACLs) and filters are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols.

These filters should be applied inbound or outbound on the appropriate external and internal interfaces.

If the router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure ACLs and filters to allow or deny traffic for specific source and destination addresses as well as ports and protocols.

Apply the filters inbound or outbound on the appropriate external and internal interfaces.

Policy-based routing can also be implemented if needed.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7358r382136_chk'
  tag severity: 'medium'
  tag gid: 'V-207097'
  tag rid: 'SV-207097r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000001'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7358r382137_fix'
  tag 'documentable'
  tag legacy: ['V-78209', 'SV-92915']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
