control 'SV-45669' do
  title 'The at daemon must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If "at" programs are located in, or subordinate, to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List any "at" jobs on the system.
Procedure:
# ls /var/spool/at /var/spool/atjobs

For each "at" job, determine which programs are executed by "at."
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-989'
  tag rid: 'SV-45669r1_rule'
  tag stig_id: 'GEN003380'
  tag gtitle: 'GEN003380'
  tag fix_id: 'F-39067r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
