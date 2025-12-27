control 'SV-227769' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29931r489661_chk'
  tag severity: 'medium'
  tag gid: 'V-227769'
  tag rid: 'SV-227769r603266_rule'
  tag stig_id: 'GEN003360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29919r489662_fix'
  tag 'documentable'
  tag legacy: ['V-988', 'SV-40411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
