control 'SV-26781' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', "Check the SSH daemon configuration for the StrictModes setting.
# grep -i StrictModes /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or not set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the StrictModes setting value to yes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-26781r1_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-24030r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
