control 'SV-256057' do
  title 'The Arista router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message being used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached its destination.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to determine if the hop limit has been configured for Router Advertisement messages. Execute the command "sh run | section hop-limit".

interface Ethernet3
  ipv6 nd ra hop-limit 32

If the router has been configured and has not been set to at least 32, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone. 

Configure the Arista router to advertise a hop limit of at least 32 in Router Advertisement messages.

LEAF-1A(config-if-Et3)#interface ethernet 3
LEAF-1A(config-if-Et3)#ipv6 nd ra hop-limit 32'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59733r882511_chk'
  tag severity: 'low'
  tag gid: 'V-256057'
  tag rid: 'SV-256057r882513_rule'
  tag stig_id: 'ARST-RT-000780'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-59676r882512_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
