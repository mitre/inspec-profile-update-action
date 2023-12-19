control 'SV-80615' do
  title 'The HP FlexFabric Switch must configure the maximum hop limit value to at least 32.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message to be used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached their destination.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if the maximum hop limit has been configured.

If the maximum hop limit is not configured, this is a finding.

If it has been configured, then it must be set to at least 32; otherwise this is a finding.

[5900CP]display current-configuration | i hop-limit
 ipv6 hop-limit 255

Note: The default value for the maximum hop limit is 64.'
  desc 'fix', 'If the max hop set is not configured then use the following command to configure it:  

[HP] ipv6 hop-limit 255'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66125'
  tag rid: 'SV-80615r2_rule'
  tag stig_id: 'HFFS-RT-000019'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-72201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
