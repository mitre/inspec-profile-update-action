control 'SV-35028' do
  title 'The system must not apply reversed source routing to TCP responses.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', "Determine if the system is configured to forward source-routed IP packets. When 
correctly configured, if ip_forward_src_routed is disabled, the system is also configured 
to disable reverse source routing to TCP responses to source-routed packets. 
# ndd -get /dev/ip ip_forward_src_routed

If the returned value is not '0', this feature is enabled and this is a finding."
  desc 'fix', 'Disable the IP source-routed forwarding feature.
# ndd -set /dev/ip ip_forward_src_routed 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x] = ip
NDD_NAME[x] = ip_forward_src_routed
NDD_VALUE[x] = 0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36505r1_chk'
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
