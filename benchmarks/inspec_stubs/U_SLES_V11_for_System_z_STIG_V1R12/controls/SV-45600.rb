control 'SV-45600' do
  title 'Crontab files must have mode 0600 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab files.
# ls -lL /etc/crontab /var/spool/cron/ /var/spool/cron/tabs/


If any crontab file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the crontab files.
# chmod 0600 /var/spool/cron/* /etc/cron.d/* /etc/crontab
# chmod 0600 /etc/crontab /var/spool/cron/* /var/spool/cron/tabs/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42966r1_chk'
  tag severity: 'medium'
  tag gid: 'V-978'
  tag rid: 'SV-45600r2_rule'
  tag stig_id: 'GEN003080'
  tag gtitle: 'GEN003080'
  tag fix_id: 'F-38998r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
