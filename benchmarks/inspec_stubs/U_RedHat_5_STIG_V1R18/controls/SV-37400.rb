control 'SV-37400' do
  title "Crontab files must be group-owned by root, cron, or the crontab creator's primary group."
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
Procedure:

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron*|grep -v deny

If the group owner is not root or the crontab owner's primary group, this is a finding."
  desc 'fix', "Change the group owner of the crontab file to root, cron, or the crontab's primary group.
Procedure:
# chgrp root [crontab file]"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36079r1_chk'
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
