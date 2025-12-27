control 'SV-218613' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Check the SSH daemon configuration for the StrictModes setting.

# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#'
 
If the setting is not present, or not set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "StrictModes" setting value to "yes".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20088r556037_chk'
  tag severity: 'medium'
  tag gid: 'V-218613'
  tag rid: 'SV-218613r603259_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20086r556038_fix'
  tag 'documentable'
  tag legacy: ['V-22485', 'SV-64067']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
