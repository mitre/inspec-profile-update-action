control 'SV-37471' do
  title 'Cron and crontab directories must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on cron and crontab directories may provide unauthorized access to these directories.  Unauthorized modifications to these directories or their contents may result in the addition of unauthorized cron jobs or deny service to authorized cron jobs.'
  desc 'check', "Check the permissions of the crontab directories.

Procedure:
# ls -ld /var/spool/cron

# ls -ld /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -ld /etc/cron*|grep -v deny

If the permissions include a '+' the directory has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the directory.
# setfacl --remove-all <crontab directory>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36138r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22387'
  tag rid: 'SV-37471r1_rule'
  tag stig_id: 'GEN003110'
  tag gtitle: 'GEN003110'
  tag fix_id: 'F-31383r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
