control 'SV-27329' do
  title 'Cron must not execute group-writable or world-writable programs.'
  desc 'If cron executes group-writable or world-writable programs, there is a possibility that unauthorized users could manipulate the programs with malicious intent.  This could compromise system and network security.'
  desc 'check', 'List all cronjobs on the system. 
Procedure: 
# ls /var/spool/cron/crontabs/

If cron jobs exist under any of the above directories search for programs executed by cron.
Procedure:
# more <cron job file>

Determine if the file is group-writable or world-writable.
Procedure:
# ls -la <cron program file>

If cron executes group-writable or world-writable files, this is a finding.'
  desc 'fix', 'Remove the world-writable and group-writable permissions from the cron program file(s) identified.
# chmod go-w <cron program file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28464r1_chk'
  tag severity: 'medium'
  tag gid: 'V-976'
  tag rid: 'SV-27329r1_rule'
  tag stig_id: 'GEN003000'
  tag gtitle: 'GEN003000'
  tag fix_id: 'F-1130r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
