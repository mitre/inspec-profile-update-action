control 'SV-46100' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', %q(Check the SSH daemon configuration for the UsePrivilegeSeparation setting.
# grep -i UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or not set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "UsePrivilegeSeparation" setting value to "yes".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22486'
  tag rid: 'SV-46100r2_rule'
  tag stig_id: 'GEN005537'
  tag gtitle: 'GEN005537'
  tag fix_id: 'F-39444r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
