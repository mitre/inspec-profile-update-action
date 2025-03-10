control 'SV-218461' do
  title 'The at daemon must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If "at" programs are located in, or subordinate, to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List any "at" jobs on the system.
Procedure:
# ls /var/spool/at

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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19936r562540_chk'
  tag severity: 'medium'
  tag gid: 'V-218461'
  tag rid: 'SV-218461r603259_rule'
  tag stig_id: 'GEN003380'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19934r562541_fix'
  tag 'documentable'
  tag legacy: ['V-989', 'SV-64475']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
