control 'SV-37594' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP Denial of Service attacks, the TCP backlog queue sizes must be set to at least 1280 or in accordance with product-specific guidelines.'
  desc 'check', '# cat /proc/sys/net/ipv4/tcp_max_syn_backlog
If the result is not 1280 or greater, this is a finding.'
  desc 'fix', 'Edit /etc/sysctl.conf and add a setting for "net.ipv4.tcp_max_syn_backlog=1280".

Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23741'
  tag rid: 'SV-37594r2_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'GEN003601'
  tag fix_id: 'F-31631r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
