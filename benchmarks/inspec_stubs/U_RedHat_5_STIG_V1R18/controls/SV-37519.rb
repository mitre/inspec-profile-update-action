control 'SV-37519' do
  title 'The "at" daemon must not execute group-writable or world-writable programs.'
  desc %q(If the "at" facility executes world-writable or group-writable programs, it is possible for the programs to be accidentally or maliciously changed or replaced without the owner's intent or knowledge.  This would cause a system security breach.)
  desc 'check', 'List the "at" jobs on the system.

Procedure:
# ls -la /var/spool/at

For each "at" job file, determine which programs are executed.

Procedure:
# more <at job file>

Check the each program executed by "at" for group- or world-writable permissions.
Procedure:
# ls -la <at program file>

If "at" executes group or world-writable programs, this is a finding.'
  desc 'fix', 'Remove group-write and world-write permissions from files executed by at jobs.

Procedure:
# chmod go-w <file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36179r1_chk'
  tag severity: 'medium'
  tag gid: 'V-988'
  tag rid: 'SV-37519r1_rule'
  tag stig_id: 'GEN003360'
  tag gtitle: 'GEN003360'
  tag fix_id: 'F-31429r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
