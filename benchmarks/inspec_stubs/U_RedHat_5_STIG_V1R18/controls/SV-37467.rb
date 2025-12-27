control 'SV-37467' do
  title 'Crontab files must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on crontab files may provide unauthorized access to the files.'
  desc 'check', "Check the permissions of the crontab files.
Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron*|grep -v deny

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [crontab file]'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22386'
  tag rid: 'SV-37467r1_rule'
  tag stig_id: 'GEN003090'
  tag gtitle: 'GEN003090'
  tag fix_id: 'F-31378r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
