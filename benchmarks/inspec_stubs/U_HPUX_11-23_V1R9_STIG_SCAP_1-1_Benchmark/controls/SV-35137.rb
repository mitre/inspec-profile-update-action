control 'SV-35137' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the StrictModes setting value to yes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-35137r1_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-30289r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
