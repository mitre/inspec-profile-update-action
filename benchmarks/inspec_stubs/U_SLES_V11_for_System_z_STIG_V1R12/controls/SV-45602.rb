control 'SV-45602' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab directories.

Procedure:
# ls -ld /var/spool/cron /var/spool/cron/tabs


ls -ld /etc/crontab /etc/cron.{d,daily,hourly,monthly,weekly}
or 
# ls -ld /etc/cron*|grep -v deny

If the mode of any of the crontab directories is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the crontab directories.
# chmod 0755 <crontab directory>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42968r1_chk'
  tag severity: 'medium'
  tag gid: 'V-979'
  tag rid: 'SV-45602r1_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'GEN003100'
  tag fix_id: 'F-39000r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
