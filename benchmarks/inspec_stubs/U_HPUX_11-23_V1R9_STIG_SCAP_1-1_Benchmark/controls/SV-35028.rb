control 'SV-35028' do
  title 'The system must not apply reversed source routing to TCP responses.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'fix', 'Disable the IP source-routed forwarding feature.
# ndd -set /dev/ip ip_forward_src_routed 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x] = ip
NDD_NAME[x] = ip_forward_src_routed
NDD_VALUE[x] = 0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22412'
  tag rid: 'SV-35028r1_rule'
  tag stig_id: 'GEN003605'
  tag gtitle: 'GEN003605'
  tag fix_id: 'F-31862r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
