control 'SV-234057' do
  title 'Firewall rules must be configured on the Tanium Server for Console-to-Server communications.'
  desc 'An HTML5 based application, the Tanium Console runs from any device with a browser that supports HTML5. For security, the HTTP and SOAP communication to the Tanium Server is SSL encrypted, so the Tanium Server installer configures the server to listen for HTTP and SOAP requests on port 443. Without a proper connection to the Tanium Server, access to the system capabilities could be denied.

Port Needed: To Tanium Server over TCP port 443.

Network firewall rules:

Allow HTTP traffic on TCP port 443 from any computer on the internal network to the Tanium Server device.

https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html.'
  desc 'check', 'Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Server.

Access the host-based firewall configuration on the Tanium Server.

Validate a rule exists for the following:
Port Needed: From only designated Tanium console user clients to Tanium Server over TCP port 443.

If a host-based firewall rule does not exist to allow only designated Tanium console user clients to Tanium Server over TCP port 443, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:
Allow TCP traffic from only designated Tanium console user clients to Tanium Server over TCP ports 443.

If a network firewall rule does not exist to allow traffic from only designated Tanium console user clients to Tanium Server over TCP port 443, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules on the Tanium Server to include the following required traffic:

Allow TCP traffic on port 433 to the Tanium Server from designated Tanium console user clients.

Configure the network firewall to allow the above traffic.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37242r610671_chk'
  tag severity: 'medium'
  tag gid: 'V-234057'
  tag rid: 'SV-234057r612749_rule'
  tag stig_id: 'TANS-CN-000014'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-37207r610672_fix'
  tag 'documentable'
  tag legacy: ['SV-102187', 'V-92085']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
