control 'SV-88785' do
  title 'The Cisco IOS XE router must not redistribute static routes to alternate gateway service provider into an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other Autonomous System.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'Review the configuration of the route connecting to the Alternate Gateway on the Cisco IOS XE router to verify that redistribution of static routes to the Alternate Gateway is not occurring by reviewing the BGP and OSPF configurations.

If the "redistribute static" command is in the configurations, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router so that static routes are not redistributed to an Alternate Gateway into either an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other Autonomous System. Use the "NO" command to disable redistribution of static routers; example below:

ISR4000(config-router)#no redistribute static'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74197r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74111'
  tag rid: 'SV-88785r2_rule'
  tag stig_id: 'CISR-RT-000008'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-80653r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
