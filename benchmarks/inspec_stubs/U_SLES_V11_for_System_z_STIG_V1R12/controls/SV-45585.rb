control 'SV-45585' do
  title 'Crontabs must be owned by root or the crontab creator.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'List all crontabs on the system. 

# ls -lL /var/spool/cron /var/spool/cron/tabs


# ls -lL /etc/crontab /etc/cron.{d,daily,hourly,monthly,weekly}
or 
# ls -lL /etc/cron*|grep -v deny

If any crontab is not owned by root or the creating user, this is a finding'
  desc 'fix', 'Change the crontab owner to root or the crontab creator.

# chown root <crontab file>
or 
# chown <user> <crontab file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11994'
  tag rid: 'SV-45585r1_rule'
  tag stig_id: 'GEN003040'
  tag gtitle: 'GEN003040'
  tag fix_id: 'F-38981r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
