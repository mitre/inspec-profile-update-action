control 'SV-234102' do
  title 'Firewall rules must be configured on the Tanium module server to allow Server-to-Module Server communications from the Tanium Server.'
  desc 'The Tanium Module Server is used to extend the functionality of Tanium through the use of various workbenches. The Tanium Module Server requires communication with the Tanium Server on port 17477. Without a proper connection from the Tanium Server to the Tanium Module Server, access to the system capabilities could be denied.

https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html.'
  desc 'check', 'Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Module Server.

Access the host-based firewall configuration on the Tanium Module Server.

Validate a rule exists for the following:
Port Needed: Tanium Server to Tanium Module Server over TCP port 17477.

If a host-based firewall rule does not exist to allow TCP port 17477, from the Tanium Server to the Tanium Module Server, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:
Allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server.

If a network firewall rule does not exist to allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules on the Tanium Module Server to include the following required traffic:

Allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server.

Configure the network firewall to allow the above traffic.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37287r610806_chk'
  tag severity: 'medium'
  tag gid: 'V-234102'
  tag rid: 'SV-234102r612749_rule'
  tag stig_id: 'TANS-SV-000031'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-37252r610807_fix'
  tag 'documentable'
  tag legacy: ['SV-102277', 'V-92175']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
