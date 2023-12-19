control 'SV-35139' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the UsePrivilegeSeparation setting value to yes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22486'
  tag rid: 'SV-35139r1_rule'
  tag stig_id: 'GEN005537'
  tag gtitle: 'GEN005537'
  tag fix_id: 'F-30291r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
