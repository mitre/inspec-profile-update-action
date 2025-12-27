control 'SV-38796' do
  title 'TCP backlog queue sizes must be set appropriately.'
  desc 'To provide some mitigation to TCP DoS attacks, the clear_partial_conns parameter must be enabled.'
  desc 'check', '# /usr/sbin/no -o clean_partial_conns
If the value returned is 0,  this is a finding.'
  desc 'fix', '# /usr/sbin/no -po clean_partial_conns=1'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37228r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23741'
  tag rid: 'SV-38796r1_rule'
  tag stig_id: 'GEN003601'
  tag gtitle: 'GEN003601'
  tag fix_id: 'F-32491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
