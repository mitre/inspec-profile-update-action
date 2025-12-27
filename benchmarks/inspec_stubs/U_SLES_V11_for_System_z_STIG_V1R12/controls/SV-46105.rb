control 'SV-46105' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'check', %q(Check the SSH daemon configuration for the RhostsRSAAuthentication setting.
# grep -i RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v '^#' 
If the setting is set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "RhostsRSAAuthentication" setting value to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22487'
  tag rid: 'SV-46105r2_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'GEN005538'
  tag fix_id: 'F-39447r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
