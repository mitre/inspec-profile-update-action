control 'SV-29690' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP Denial of Service (DoS) attacks, the TCP backlog queue sizes must be set to at least 1280 or in accordance with product-specific guidelines.'
  desc 'fix', 'Set the tcp_syn_rcvd_max parameter to 1280.
# ndd -set /dev/tcp tcp_syn_rcvd_max 1280

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x] = tcp
NDD_NAME[x] = tcp_syn_rcvd_max
NDD_VALUE[x] = 1280'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-23741'
  tag rid: 'SV-29690r1_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'GEN003601'
  tag fix_id: 'F-26884r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
