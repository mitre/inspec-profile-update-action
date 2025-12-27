control 'SV-45580' do
  title 'Cron must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If cron programs are located in or subordinate to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List all cronjobs on the system. 
Procedure:

# ls /var/spool/cron /var/spool/cron/tabs


# ls /etc/crontab /etc/cron.{d,daily,hourly,monthly,weekly}
or 
# ls /etc/cron*|grep -v deny


If cron jobs exist under any of the above directories, use the following command to search for programs executed by at:

# more <cron job file>

Perform a long listing of each directory containing program files found in the cron file to determine if the directory is world-writable.

# ls -ld <cron program directory>

If cron executes programs in world-writable directories, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the cron program directories identified.

Procedure:
# chmod o-w <cron program directory>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-977'
  tag rid: 'SV-45580r1_rule'
  tag stig_id: 'GEN003020'
  tag gtitle: 'GEN003020'
  tag fix_id: 'F-38977r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
