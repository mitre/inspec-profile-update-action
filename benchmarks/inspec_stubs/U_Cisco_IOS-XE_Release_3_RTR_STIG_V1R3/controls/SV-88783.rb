control 'SV-88783' do
  title 'The Cisco IOS XE router must not be a BGP peer with a router from an Autonomous System belonging to any Alternate Gateway.'
  desc 'The perimeter router will not use a routing protocol to advertise NIPRNet addresses to Alternate Gateways. Most ISPs use Border Gateway Protocol (BGP) to share route information with other autonomous systems, that is, any network under a different administrative control and policy than a local site. If BGP is configured on the perimeter router, no BGP neighbors will be defined to peer routers from an AS belonging to any Alternate Gateway. The only allowable method is a static route to reach the Alternate Gateway.'
  desc 'check', 'Review the configuration of the Cisco IOS XE router connecting to the Alternate Gateway.

Verify there are no BGP neighbors configured to the remote AS that belongs to the Alternate Gateway service provider.

If there are BGP neighbors connecting the remote AS of the Alternate Gateway service provider, this is a finding.'
  desc 'fix', 'Configure a static route on the perimeter Cisco IOS XE router to reach the AS of a router connecting to an Alternate Gateway, using the following command:

ISR4000 (config) #ip route <Destination Prefix> <Destination Prefix mask> <Forwarding routers address>

The configuration would look similar to the example below:

ip route 1.1.1.0 255.255.255.0 2.2.2.2'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74195r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74109'
  tag rid: 'SV-88783r2_rule'
  tag stig_id: 'CISR-RT-000007'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-80651r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
