control 'SV-977' do
  title 'Cron must not execute programs in, or subordinate to, world-writable directories.'
  desc 'If cron programs are located in or subordinate to world-writable directories, they become vulnerable to removal and replacement by malicious users or system intruders.'
  desc 'check', 'List all cron jobs on the system.  If any cron job executes a program located in a world-writable directory, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the cron program directories identified.

Procedure:
# chmod o-w <cron program directory>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-789r2_chk'
  tag severity: 'medium'
  tag gid: 'V-977'
  tag rid: 'SV-977r2_rule'
  tag stig_id: 'GEN003020'
  tag gtitle: 'GEN003020'
  tag fix_id: 'F-1131r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
