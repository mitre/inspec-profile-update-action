control 'SV-38362' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If there are excessive file permissions for the cron.deny file, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the permissions of the crontab files for an ACL.
# ls -lL /var/adm/cron/cron.deny

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /var/adm/cron/cron.deny'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22389'
  tag rid: 'SV-38362r1_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'GEN003210'
  tag fix_id: 'F-31816r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
