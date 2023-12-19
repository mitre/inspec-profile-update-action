control 'SV-38822' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', '# /usr/sbin/no -o ip6forwarding
If the value returned is 1, this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding on the system. 
# /usr/sbin/no -p -o ip6forwarding=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37068r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22491'
  tag rid: 'SV-38822r1_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'GEN005610'
  tag fix_id: 'F-32335r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
