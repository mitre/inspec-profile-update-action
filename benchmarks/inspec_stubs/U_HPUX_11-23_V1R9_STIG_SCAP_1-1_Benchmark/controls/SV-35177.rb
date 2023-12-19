control 'SV-35177' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'fix', 'Edit /etc/rc.config.d/nddconf and set the ip_forwarding option to 0.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-12023'
  tag rid: 'SV-35177r1_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'GEN005600'
  tag fix_id: 'F-32046r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
