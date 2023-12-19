control 'SV-226864' do
  title 'The "at" daemon must not execute group-writable or world-writable programs.'
  desc %q(If the "at" facility executes world-writable or group-writable programs, it is possible for the programs to be accidentally or maliciously changed or replaced without the owner's intent or knowledge.  This would cause a system security breach.)
  desc 'check', 'List the "at" jobs on the system.
Procedure:
# ls -la /var/spool/cron/atjobs

For each "at" job file, determine which programs are executed.
Procedure:
# more <at job file>

Check each program executed by "at" for group- or world-writable permissions.
Procedure:
# ls -la <at program file>

If "at" executes group- or world-writable programs, this is a finding.'
  desc 'fix', 'Remove group-write and world-write permissions from files executed by "at" jobs.
Procedure:
# chmod go-w <file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29026r484876_chk'
  tag severity: 'medium'
  tag gid: 'V-226864'
  tag rid: 'SV-226864r603265_rule'
  tag stig_id: 'GEN003360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29014r484877_fix'
  tag 'documentable'
  tag legacy: ['SV-40411', 'V-988']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
