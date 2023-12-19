control 'SV-27362' do
  title 'The cron.deny file must have mode 0600 or less permissive.'
  desc 'If file permissions for cron.deny are more permissive than 0600, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the mode of the cron.deny file.
# ls -lL /etc/cron.deny
If the cron.deny file does not exist this is not a finding.
If the cron.deny file exists and the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron.deny file.
# chmod 0600 /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-28506r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4358'
  tag rid: 'SV-27362r1_rule'
  tag stig_id: 'GEN003200'
  tag gtitle: 'GEN003200'
  tag fix_id: 'F-24608r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
