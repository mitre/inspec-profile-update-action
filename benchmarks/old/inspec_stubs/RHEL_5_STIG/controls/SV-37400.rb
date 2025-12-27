control 'SV-37400' do
  title "Crontab files must be group-owned by root, cron, or the crontab creator's primary group."
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'fix', "Change the group owner of the crontab file to root, cron, or the crontab's primary group.
Procedure:
# chgrp root [crontab file]"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22385'
  tag rid: 'SV-37400r1_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'GEN003050'
  tag fix_id: 'F-31323r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
