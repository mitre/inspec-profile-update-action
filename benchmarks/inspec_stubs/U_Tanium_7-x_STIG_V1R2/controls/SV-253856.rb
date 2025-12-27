control 'SV-253856' do
  title 'Firewall rules must be configured on the Tanium module server to allow Server-to-Module Server communications from the Tanium Server.'
  desc 'The Tanium Module Server is used to extend the functionality of Tanium through the use of various workbenches. The Tanium Module Server requires communication with the Tanium Server on port 17477. Without a proper connection from the Tanium Server to the Tanium Module Server, access to the system capabilities could be denied.

For more information, refer to https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html.'
  desc 'check', 'Consult with the Tanium system administrator to verify which firewall is being used as a host-based firewall on the Tanium Module Server.

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the host-based firewall configuration on the Tanium Module Server.

4. Validate a rule exists for the following:

Port Needed: Tanium Server to Tanium Module Server over TCP port 17477.

If a host-based firewall rule does not exist to allow TCP port 17477 from the Tanium Server to the Tanium Module Server, this is a finding.

Consult with the network firewall administrator and validate rules exist for the following:

Allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server.

If a network firewall rule does not exist to allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server, this is a finding.'
  desc 'fix', '1. Configure host-based firewall rules on the Tanium Module Server to include the following required traffic:

Allow TCP traffic on port 17477 from the Tanium Server to the Tanium Module Server.

2. Configure the network firewall to allow the above traffic.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57308r842594_chk'
  tag severity: 'medium'
  tag gid: 'V-253856'
  tag rid: 'SV-253856r850218_rule'
  tag stig_id: 'TANS-SV-000031'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-57259r842595_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
