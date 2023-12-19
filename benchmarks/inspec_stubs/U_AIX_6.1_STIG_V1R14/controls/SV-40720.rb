control 'SV-40720' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Check the SSH daemon configuration for the StrictModes setting.

# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#'

If the setting is present and set to "no", this is a finding.  If the setting is not present or is set to "yes", this is not a finding.)
  desc 'fix', 'Edit the /etc/sshd/sshd_config file and remove the StrictModes setting or change the value of the StrictModes setting to "yes".'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39451r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-40720r1_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-34579r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
