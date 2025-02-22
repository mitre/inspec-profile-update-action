control 'SV-38360' do
  title 'Cron and crontab directories must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured. ACLs on cron and crontab directories may provide unauthorized access to these directories. Unauthorized modifications to these directories or their contents may result in the addition of unauthorized cron jobs or deny service to authorized cron jobs.'
  desc 'check', 'Check the permissions of the crontab directories.
# ls -ld /var/spool/cron/crontabs

If the permissions include a "+", the directory has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the directory.
# chacl -z <crontab directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36471r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22387'
  tag rid: 'SV-38360r1_rule'
  tag stig_id: 'GEN003110'
  tag gtitle: 'GEN003110'
  tag fix_id: 'F-31814r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
