control 'SV-37900' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "StrictModes" setting value to "yes".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-37900r2_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-32394r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
