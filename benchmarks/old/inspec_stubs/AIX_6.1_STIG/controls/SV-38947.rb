control 'SV-38947' do
  title 'Cron must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If cron programs are located in or subordinate to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List all cronjobs on the system.
Procedure:
# ls /var/spool/cron/crontabs/

If cron jobs exist under any of the above directories search for programs executed by cron.
Procedure:
# more <cron job file>

Determine if the directory containing programs executed from cron is world-writable.
Procedure:
# ls -ld <cron program directory>

If cron executes programs in world-writable directories, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the cron program directories identified.

Procedure:
# chmod o-w <cron program directory>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28466r1_chk'
  tag severity: 'medium'
  tag gid: 'V-977'
  tag rid: 'SV-38947r1_rule'
  tag stig_id: 'GEN003020'
  tag gtitle: 'GEN003020'
  tag fix_id: 'F-32473r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
