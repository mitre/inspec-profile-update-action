control 'SV-35146' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the Compression setting value to no or delayed.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22488'
  tag rid: 'SV-35146r1_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'GEN005539'
  tag fix_id: 'F-30297r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
