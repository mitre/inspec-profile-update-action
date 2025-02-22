control 'SV-39103' do
  title 'Cron and crontab directories must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured. ACLs on cron and crontab directories may provide unauthorized access to these directories. Unauthorized modifications to these directories or their contents may result in the addition of unauthorized cron jobs or deny service to authorized cron jobs.'
  desc 'check', 'Check the permissions of the crontab directories.

# ls -lL /var/spool/cron/crontabs
# aclget < crontab >
# aclget /var/spool/cron

Check if extended permissions are disabled. If extended permissions are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the crontab file(s) and disable extended permissions. 

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38094r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22387'
  tag rid: 'SV-39103r1_rule'
  tag stig_id: 'GEN003110'
  tag gtitle: 'GEN003110'
  tag fix_id: 'F-33356r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
