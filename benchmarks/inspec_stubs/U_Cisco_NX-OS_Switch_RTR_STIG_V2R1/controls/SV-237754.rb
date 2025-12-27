control 'SV-237754' do
  title 'The Cisco switch must be configured to advertise a hop limit of at least 32 in Switch Advertisement messages for IPv6 stateless auto-configuration deployments.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message being used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached its destination.'
  desc 'check', 'Review the switch configuration to determine if the hop limit has been configured for Router Advertisement messages for all internal interfaces as shown in the example.

interface Ethernet2/1
  no switchport
  ipv6 address 2001::1:0:1/64
  ipv6 nd hop-limit 32
  no shutdown 

interface Ethernet2/2
  no switchport
  ipv6 address 2001::1:1:1/64
  ipv6 nd hop-limit 32
  no shutdown 

If hop-limit has been configured and has not been set to at least 32, it is a finding.'
  desc 'fix', 'Configure the switch to advertise a hop limit of at least 32 in Router Advertisement messages as shown in the example.

SW1(config)#  interface e2/1 – 2
SW1(config-if-range)#  ipv6 nd hop-limit 32
SW1(config-if-range)#  end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-40972r648781_chk'
  tag severity: 'low'
  tag gid: 'V-237754'
  tag rid: 'SV-237754r648783_rule'
  tag stig_id: 'CISC-RT-000236'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-40934r648782_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
