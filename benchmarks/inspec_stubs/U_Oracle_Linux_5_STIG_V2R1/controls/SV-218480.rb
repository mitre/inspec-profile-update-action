control 'SV-218480' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP Denial of Service attacks, the TCP backlog queue sizes must be set to at least 1280 or in accordance with product-specific guidelines.'
  desc 'check', '# cat /proc/sys/net/ipv4/tcp_max_syn_backlog
If the result is not 1280 or greater, this is a finding.'
  desc 'fix', 'Edit /etc/sysctl.conf and add a setting for "net.ipv4.tcp_max_syn_backlog=1280".

Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19955r555638_chk'
  tag severity: 'medium'
  tag gid: 'V-218480'
  tag rid: 'SV-218480r603259_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19953r555639_fix'
  tag 'documentable'
  tag legacy: ['V-23741', 'SV-64457']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
