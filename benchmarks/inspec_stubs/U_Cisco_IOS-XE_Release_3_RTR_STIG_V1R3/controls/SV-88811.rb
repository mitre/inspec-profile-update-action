control 'SV-88811' do
  title 'The Cisco IOS XE router must configure the maximum hop limit value to at least 32.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message to be used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached their destination.'
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if the maximum hop limit for IPv6 Neighbor Discovery has been configured.

The configuration would look similar to the example below:

ipv6 hop-limit 32

If the router does not have the maximum hop limit value set to at least "32", this is a finding.

If it has been configured, then it must be set to at least "32".

If it has not been configured, it must be determined what the default value is.

If the default value is below "32" and the maximum hop limit value has not been configured (set to at least "32"), this is a finding.

In any case, maximum hop limit must be at least "32".'
  desc 'fix', 'Configure the Cisco IOS XE router IPv6 Neighbor Discovery maximum hop limit value to at least "32".

The configuration would look similar to the example below:

ipv6 hop-limit 32'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74223r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74137'
  tag rid: 'SV-88811r2_rule'
  tag stig_id: 'CISR-RT-000022'
  tag gtitle: 'SRG-NET-000205-RTR-000108'
  tag fix_id: 'F-80679r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
