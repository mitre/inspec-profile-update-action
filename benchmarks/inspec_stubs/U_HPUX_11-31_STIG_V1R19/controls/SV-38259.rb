control 'SV-38259' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine if the system is configured to forward source-routed IP packets.
# ndd -get /dev/ip ip_forward_src_routed

If the returned value is not 0, then this feature is enabled, this is a finding.'
  desc 'fix', 'Disable the IP source-routed forwarding feature.
# ndd -set /dev/ip ip_forward_src_routed 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x] = ip
NDD_NAME[x] = ip_forward_src_routed
NDD_VALUE[x] = 0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36500r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12002'
  tag rid: 'SV-38259r1_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'GEN003600'
  tag fix_id: 'F-31855r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
