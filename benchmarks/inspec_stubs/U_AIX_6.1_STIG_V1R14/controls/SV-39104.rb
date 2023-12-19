control 'SV-39104' do
  title 'Cron and crontab directories must be group-owned by system, sys, bin, or cron.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of cron and crontab directories. 

Procedure:
# ls -ld /var/spool/cron/crontabs

If a cron or crontab directory is not group-owned by sys,  system, bin, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of the crontab directories to sys, system, bin, or cron. 
Procedure: # 
chown cron /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-981'
  tag rid: 'SV-39104r1_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'GEN003140'
  tag fix_id: 'F-33357r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
