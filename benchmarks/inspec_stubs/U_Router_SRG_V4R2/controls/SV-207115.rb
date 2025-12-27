control 'SV-207115' do
  title 'The perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone. 

Review the configuration of the router connecting to the alternate gateway and verify that redistribution of static routes to the alternate gateway is not occurring. 

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering with a NIPRNet gateway or another autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router so that static routes are not redistributed to an alternate gateway into either an Exterior Gateway Protocol or Interior Gateway Protocol to the NIPRNet or to other autonomous systems.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7376r382238_chk'
  tag severity: 'low'
  tag gid: 'V-207115'
  tag rid: 'SV-207115r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000010'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7376r382239_fix'
  tag 'documentable'
  tag legacy: ['V-55735', 'SV-69989']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
