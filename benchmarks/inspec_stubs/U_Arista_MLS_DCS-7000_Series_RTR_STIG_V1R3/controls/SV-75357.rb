control 'SV-75357' do
  title 'If Border Gateway Protocol (BGP) is enabled on The Arista Multilayer Switch, The Arista Multilayer Switch must not be a BGP peer with a router from an Autonomous System belonging to any Alternate Gateway.'
  desc 'The perimeter router will not use a routing protocol to advertise NIPRNet addresses to Alternate Gateways. Most ISPs use Border Gateway Protocol (BGP) to share route information with other autonomous systems, that is, any network under a different administrative control and policy than a local site. If BGP is configured on the perimeter router, no BGP neighbors will be defined to peer routers from an AS belonging to any Alternate Gateway. The only allowable method is a static route to reach the Alternate Gateway.'
  desc 'check', 'This requirement applies only to DoDIN enclaves. Review the configuration of the router connecting to the Alternate Gateway via the "show router bgp [processID]" command.

Verify there are no BGP neighbors configured to the remote AS that belongs to the Alternate Gateway service provider.

If there are BGP neighbors connecting the remote AS of the Alternate Gateway service provider, this is a finding.'
  desc 'fix', 'Configure a static route on the perimeter router to reach the AS of a router connecting to an Alternate Gateway

Ip route [destination/mask] [forwarding interface]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60899'
  tag rid: 'SV-75357r1_rule'
  tag stig_id: 'AMLS-L3-000160'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-66611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
