control 'SV-39866' do
  title "Crontab files must be group-owned by system, cron, or the crontab creator's primary group."
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
# ls -lL /var/spool/cron/crontabs/
If the group owner is not system, cron, or the crontab owner's primary group, this is a finding."
  desc 'fix', "Change the group owner of the crontab file to system, cron, or the crontab's primary group.
Procedure:
# chgrp cron [crontab file]"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22385'
  tag rid: 'SV-39866r1_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'GEN003050'
  tag fix_id: 'F-34015r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
