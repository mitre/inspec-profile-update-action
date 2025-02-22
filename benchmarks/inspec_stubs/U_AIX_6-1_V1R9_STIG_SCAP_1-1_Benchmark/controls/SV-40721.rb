control 'SV-40721' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and remove the UsePrivilegeSeparation setting or change the value of the UsePrivilegeSeparation setting to "yes".'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22486'
  tag rid: 'SV-40721r1_rule'
  tag stig_id: 'GEN005537'
  tag gtitle: 'GEN005537'
  tag fix_id: 'F-34580r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
