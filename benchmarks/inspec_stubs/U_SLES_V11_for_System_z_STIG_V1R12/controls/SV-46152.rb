control 'SV-46152' do
  title 'The centralized process core dump data directory must be owned by root.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Procedure:
Check the defined directory for process core dumps.
# cat /proc/sys/kernel/core_pattern|xargs -n1 -IPATTERN dirname PATTERN

Check the existence and ownership of the directory
# ls -lLd <core file directory>
If the directory does not exist or is not owned by root, this is a finding.'
  desc 'fix', 'If the core file directory does not exist it must be created.
# mkdir -p <core file directory>

If necessary, change the owner of the core file directory.
# chown root <core file directory>'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43413r1_chk'
  tag severity: 'low'
  tag gid: 'V-22400'
  tag rid: 'SV-46152r1_rule'
  tag stig_id: 'GEN003502'
  tag gtitle: 'GEN003502'
  tag fix_id: 'F-39491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
