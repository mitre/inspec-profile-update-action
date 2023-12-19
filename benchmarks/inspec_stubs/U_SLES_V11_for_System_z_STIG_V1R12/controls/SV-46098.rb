control 'SV-46098' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Check the SSH daemon configuration for the StrictModes setting.
# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or not set to "yes", this is a finding.)
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and add or edit the "StrictModes" setting value to "yes".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43355r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-46098r2_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-39442r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
