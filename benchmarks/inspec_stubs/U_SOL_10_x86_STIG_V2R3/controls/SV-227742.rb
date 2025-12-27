control 'SV-227742' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29904r488810_chk'
  tag severity: 'medium'
  tag gid: 'V-227742'
  tag rid: 'SV-227742r603266_rule'
  tag stig_id: 'GEN003020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29892r488811_fix'
  tag 'documentable'
  tag legacy: ['V-977', 'SV-27331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
