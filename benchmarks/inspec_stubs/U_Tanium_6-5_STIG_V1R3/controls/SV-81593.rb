control 'SV-81593' do
  title 'Firewall rules must be configured on the Tanium module server to allow Server-to-Module Server communications from the Tanium Server.'
  desc 'Tanium 6.5 introduces the Tanium Module Server (formerly known as the Tanium Plugin Server) used to extend the functionality of Tanium through the use of various workbenches. The Tanium Module Server requires communication with the Tanium Server on port 17477.

https://kb.tanium.com/Port_Configuration_v6.5'
  desc 'check', 'Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Module Server.

Access the host-based firewall configuration on the Tanium Module Server.

Validate a rule exists for the following:
Port Needed: Tanium Server to Tanium Module Server over TCP port 17477.

If a host-based firewall rule does not exist to allow TCP port 17477, from the Tanium Server to the Tanium Module Server, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:
Allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server.

If a network firewall rule does not exist to allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules on the Tanium Module server to include the following required traffic:

Allow TCP traffic on port 17477 from the Tanium Server.

Configure the network firewall to allow the above traffic.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67103'
  tag rid: 'SV-81593r1_rule'
  tag stig_id: 'TANS-SV-000031'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-73203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
