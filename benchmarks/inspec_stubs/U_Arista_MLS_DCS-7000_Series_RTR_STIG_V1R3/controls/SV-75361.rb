control 'SV-75361' do
  title 'The Arista Multilayer Switch must not redistribute static routes to alternate gateway service provider into an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other Autonomous System.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement applies only to DoDIN enclaves. Review the configuration of the route connecting to the Alternate Gateway.

Verify redistribution of static routes to the Alternate Gateway is not occurring by reviewing the running configuration via the "show running-config" command. In the appropriate routing protocol configuration, there must not be a "redistribute static" statement. If there is a redistribute static statement, there must be an accompanying route map to prevent redistribution of routes to the alternate gateway.

If the static routes to the Alternate Gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this is a finding.'
  desc 'fix', 'Configure the router so that static routes are not redistributed to an Alternate Gateway into either an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other Autonomous System. Enter "no redistribute static" into the routing process configuration to fulfill this requirement.

To configure a Route Map to allow for redistribution of some static routes, refer to Chapter 18.3 of the Arista Configuration Manual.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60903'
  tag rid: 'SV-75361r1_rule'
  tag stig_id: 'AMLS-L3-000170'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-66615r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
