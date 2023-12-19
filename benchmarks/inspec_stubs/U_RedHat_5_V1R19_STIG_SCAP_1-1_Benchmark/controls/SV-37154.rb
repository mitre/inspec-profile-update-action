control 'SV-37154' do
  title 'All user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'fix', 'Change the mode of user home directories to 0750 or less permissive.

Procedure (example):
# chmod 0750 <home directory>

Note: Application directories are allowed and may need 0755 permissions (or greater) for correct operation.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-901'
  tag rid: 'SV-37154r1_rule'
  tag stig_id: 'GEN001480'
  tag gtitle: 'GEN001480'
  tag fix_id: 'F-32772r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
