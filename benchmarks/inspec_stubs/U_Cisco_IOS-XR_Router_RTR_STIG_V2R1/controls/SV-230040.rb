control 'SV-230040' do
  title 'The Cisco router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message being used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached its destination.'
  desc 'check', 'Review the router configuration to determine if the hop limit has been configured for Router Advertisement messages as shown in the example.

ipv6 hop-limit 128

If it has been configured and has not been set to at least 32, it is a finding.'
  desc 'fix', 'Configure the router to advertise a hop limit of at least 32 in Router Advertisement messages.

R1(config)#ipv6 hop-limit 128'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-32352r531382_chk'
  tag severity: 'low'
  tag gid: 'V-230040'
  tag rid: 'SV-230040r532994_rule'
  tag stig_id: 'CISC-RT-000236'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-32329r531385_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
