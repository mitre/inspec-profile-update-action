control 'SV-93389' do
  title 'Firewall rules must be configured on the Tanium Zone Server for Client-to-Zone Server communications.'
  desc 'In customer environments using the Tanium Zone Server, a Tanium Client may be configured to point to a Zone Server instead of a Tanium Server. The communication requirements for these Clients are identical to the Server-to-Client requirements.

https://docs.tanium.com/platform_install/platform_install/reference_network_ports.html'
  desc 'check', 'Note: If a Zone Server is not being used, this is "Not Applicable".

Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Zone Server.

Access the host-based firewall configuration on the Tanium Zone Server.

Validate a rule exists for the following:
Port Needed: Tanium Clients to Zone Server over TCP port 17472.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, from Tanium Clients to the Tanium Zone Server, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules as required, to include Tanium Clients to Zone Server over TCP port 17472.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78253r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78683'
  tag rid: 'SV-93389r1_rule'
  tag stig_id: 'TANS-SV-000018'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-85419r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
