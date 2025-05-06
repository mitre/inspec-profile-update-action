control 'SV-4358' do
  title 'The cron.deny file must have mode 0600 or less permissive.'
  desc 'If file permissions for cron.deny are more permissive than 0600, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the mode of the cron.deny file.  If the cron.deny file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.deny file to 0600.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4358'
  tag rid: 'SV-4358r2_rule'
  tag stig_id: 'GEN003200'
  tag gtitle: 'GEN003200'
  tag fix_id: 'F-11473r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
