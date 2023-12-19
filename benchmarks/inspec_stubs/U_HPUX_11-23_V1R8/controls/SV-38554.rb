control 'SV-38554' do
  title 'The at daemon must not execute group-writable or world-writable programs.'
  desc "If the at facility executes group- or world-writable programs, it is possible for the programs to be accidentally or maliciously changed or replaced without the owner's intent or knowledge. This would cause a system security breach."
  desc 'check', 'List the at jobs on the system.
Procedure:
# ls -lLa /var/spool/cron/atjobs

For each at job file, determine which programs are executed.
# more <at job file>

Check each program executed by at for group- or world-writable permissions.
# ls -lLa <at program file>

If at executes programs that are group- or world-writable, this is a finding.'
  desc 'fix', 'Remove group-write and world-write permissions from files executed by at jobs.
# chmod go-w <file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36461r1_chk'
  tag severity: 'medium'
  tag gid: 'V-988'
  tag rid: 'SV-38554r1_rule'
  tag stig_id: 'GEN003360'
  tag gtitle: 'GEN003360'
  tag fix_id: 'F-31801r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
