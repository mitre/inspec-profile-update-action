control 'SV-218460' do
  title 'The at daemon must not execute group-writable or world-writable programs.'
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19935r562537_chk'
  tag severity: 'medium'
  tag gid: 'V-218460'
  tag rid: 'SV-218460r603259_rule'
  tag stig_id: 'GEN003360'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19933r562538_fix'
  tag 'documentable'
  tag legacy: ['V-988', 'SV-64469']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
