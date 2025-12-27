control 'SV-27360' do
  title 'The cron.deny file must have mode 0600 or less permissive.'
  desc 'If file permissions for cron.deny are more permissive than 0600, sensitive information could be viewed or edited by unauthorized users.'
  desc 'fix', 'Change the mode of the cron.deny file.
# chmod 0600 /var/adm/cron/cron.deny'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-4358'
  tag rid: 'SV-27360r1_rule'
  tag stig_id: 'GEN003200'
  tag gtitle: 'GEN003200'
  tag fix_id: 'F-24606r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
