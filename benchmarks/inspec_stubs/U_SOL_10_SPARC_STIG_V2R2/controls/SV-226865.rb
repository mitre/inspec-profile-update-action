control 'SV-226865' do
  title 'The "at" daemon must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If "at" programs are located in or subordinate to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List any "at" jobs on the system.
Procedure:
# ls /var/spool/cron/atjobs

For each "at" job, determine which programs are executed.
Procedure:
# more <at job file>

Check the directory containing each program executed by "at" for world-writable permissions.
Procedure:
# ls -la <at program file directory>

If "at" executes programs in world-writable directories, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from directories containing programs executed by "at".

Procedure:
# chmod o-w <at program directory>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29027r484879_chk'
  tag severity: 'medium'
  tag gid: 'V-226865'
  tag rid: 'SV-226865r603265_rule'
  tag stig_id: 'GEN003380'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29015r484880_fix'
  tag 'documentable'
  tag legacy: ['V-989', 'SV-40412']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
