control 'SV-81511' do
  title 'Firewall rules must be configured on the Tanium Server for Console-to-Server communications.'
  desc 'An HTML5/Adobe Flash based application, the Tanium Console runs from any device with a browser configured with Adobe Flash Player 11.5 or higher. For security, the TCP and SOAP communication to the Tanium Server is SSL encrypted, so the Tanium Server installer configures the server to listen for TCP and SOAP requests on port 443. If another installed application is listening on port 443, you can designate a different port for TCP and SOAP communication when installing the Tanium Server.

Port Needed: To Tanium Server over TCP ports 443, 17440, and 17441

Network firewall rules:

Allow TCP traffic on port 443 from any computer on the internal network to the Tanium Server device

Allow TCP traffic on port 17440 from any computer on the internal network to the Tanium Server device (Patch Workbench)

https://kb.tanium.com/Port_Configuration_v6.5'
  desc 'check', 'Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Server.

Access the host-based firewall configuration on the Tanium Server.

Validate a rule exists for the following:
Port Needed: From only designated Tanium console user clients to Tanium Server over TCP ports 443, 17440, and 17441.

If a host-based firewall rule does not exist to allow only designated Tanium console user clients to Tanium Server over TCP ports 443, 17440, and 17441, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:
Allow TCP traffic from only designated Tanium console user clients to Tanium Server over TCP ports 443, 17440, and 17441.

If a network firewall rule does not exist to allow traffic from only designated Tanium console user clients to Tanium Server over TCP ports 443, 17440, and 17441, this is a finding.'
  desc 'fix', 'Configure host-based and network firewall rules as required.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67657r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67021'
  tag rid: 'SV-81511r1_rule'
  tag stig_id: 'TANS-CN-000014'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-73121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
