control 'SV-38701' do
  title 'The system must provide protection for the TCP stack against connection resets, SYN, and data injection attacks.'
  desc "The tcp_tcpsecure parameter provides protection for TCP connections from fake SYN's, fake RST, and data injections on established connections.  The first vulnerability involves sending a fake SYN to an established connection to abort the connection. The second vulnerability involves sending a fake RST to an established connection to abort the connection. The third vulnerability involves injecting fake data in an established TCP connection."
  desc 'fix', 'Set the tcp_tcpsecure parameter to 7.

# /usr/sbin/no -p -o tcp_tcpsecure=7'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29497'
  tag rid: 'SV-38701r1_rule'
  tag stig_id: 'GEN000000-AIX0220'
  tag gtitle: 'GEN000000-AIX0220'
  tag fix_id: 'F-33055r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
