control 'SV-218433' do
  title 'Crontabs must be owned by root or the crontab creator.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'List all crontabs on the system. 

# ls -lL /var/spool/cron

# ls -lL /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -lL /etc/cron*|grep -v deny

If any crontab is not owned by root or the creating user, this is a finding.'
  desc 'fix', 'Change the crontab owner to root or the crontab creator.

# chown root <crontab file>
or 
# chown <user> <crontab file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19908r562459_chk'
  tag severity: 'medium'
  tag gid: 'V-218433'
  tag rid: 'SV-218433r603259_rule'
  tag stig_id: 'GEN003040'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19906r562460_fix'
  tag 'documentable'
  tag legacy: ['V-11994', 'SV-64401']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
