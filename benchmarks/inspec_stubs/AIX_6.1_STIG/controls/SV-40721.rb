control 'SV-40721' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', %q(Check the SSH daemon configuration for the UsePrivilegeSeparation setting.

# grep -i UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v '^#'

If the setting is present and set to "no", this is a finding.  If the setting is not present or is set to "yes", this is not a finding.)
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and remove the UsePrivilegeSeparation setting or change the value of the UsePrivilegeSeparation setting to "yes".'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39452r1_chk'
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
