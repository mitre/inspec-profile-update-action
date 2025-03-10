control 'SV-81569' do
  title 'Firewall rules must be configured on the Tanium Zone Server for Client-to-Zone Server communications.'
  desc 'In customer environments using the Tanium Zone Server, a Tanium Client may be configured to point to a Zone Server instead of a Tanium Server. The communication requirements for these Clients are identical to the Server-to-Client requirements. 

https://kb.tanium.com/Port_Configuration_v6.5'
  desc 'check', 'Note: If a zone server is not being used, this is Not Applicable.

Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Zone Server.

Access the host-based firewall configuration on the Tanium Zone Server.

Validate a rule exists for the following:
Port Needed: Tanium Clients to Zone Server over TCP port 17472.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, from Tanium Clients to the Tanium Zone Server, this is a finding.'
  desc 'fix', 'Configure host-based firewall rules as required, to include Tanium Clients to Zone Server over TCP port 17472.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67715r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67079'
  tag rid: 'SV-81569r1_rule'
  tag stig_id: 'TANS-SV-000018'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-73179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
