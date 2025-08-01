control 'SV-45596' do
  title 'Crontab files must be group-owned by root, cron, or the crontab creators primary group.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
Procedure:

# ls -lL /var/spool/cron /var/spool/cron/tabs


# ls -lL /etc/crontab /etc/cron.{d,daily,hourly,monthly,weekly}
or 
# ls -lL /etc/cron*|grep -v deny

If the group owner is not root or the crontab owner's primary group, this is a finding."
  desc 'fix', "Change the group owner of the crontab file to root, cron, or the crontab's primary group.
Procedure:
# chgrp root [crontab file]"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42954r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22385'
  tag rid: 'SV-45596r1_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'GEN003050'
  tag fix_id: 'F-38994r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
