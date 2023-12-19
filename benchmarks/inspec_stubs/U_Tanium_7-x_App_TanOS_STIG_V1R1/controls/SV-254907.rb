control 'SV-254907' do
  title 'Firewall rules must be configured on the Tanium Zone Server for Client-to-Zone Server communications.'
  desc 'In customer environments using the Tanium Zone Server, a Tanium Client may be configured to point to a Zone Server instead of a Tanium Server. The communication requirements for these Clients are identical to the Server-to-Client requirements. Without proper firewall configurations, proper TCP communications may not take place as necessary for application functionality. Additionally, without proper configuration, organizations may lose complete visibility into endpoints that cannot connect directly to the Tanium Server. 

https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/network_ports.html'
  desc 'check', 'Note: If a Zone Server is not being used, this is Not Applicable.

1. Consult with the Tanium System Administrator to verify which firewall is being used as a host-based firewall on the Tanium Zone Server.

2. Access the host-based firewall configuration on the Tanium Zone Server.

3. Validate a rule exists for the following:

3A. Port Needed: Tanium Clients to Zone Server over TCP port 17472, bi-directionally.

If a host-based firewall rule does not exist to allow TCP port 17472, bi-directionally, from Tanium Clients to the Tanium Zone Server, this is a finding.'
  desc 'fix', '1. Consult with the personnel who maintain the Enterprise Security Suite to configure host-based and network firewall rules to allow the following:

1A. Tanium Clients or Zone Clients over TCP port 17472, bi-directionally.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58520r867619_chk'
  tag severity: 'medium'
  tag gid: 'V-254907'
  tag rid: 'SV-254907r867621_rule'
  tag stig_id: 'TANS-AP-000365'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-58464r867620_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
