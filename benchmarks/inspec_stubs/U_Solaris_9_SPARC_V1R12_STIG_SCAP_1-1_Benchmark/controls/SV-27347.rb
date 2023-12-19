control 'SV-27347' do
  title 'Cron and crontab directories must be group-owned by root, sys, or bin.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group-ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group owner of the crontab directories to root, sys, or bin.

Procedure:
# chgrp root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-981'
  tag rid: 'SV-27347r1_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'GEN003140'
  tag fix_id: 'F-24590r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
