control 'SV-46154' do
  title 'The centralized process core dump data directory must have mode 0700 or less permissive.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the process core dump data directory has a mode more permissive than 0700, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', 'Procedure:
Check the defined directory for process core dumps.
# cat /proc/sys/kernel/core_pattern|xargs -n1 -IPATTERN dirname PATTERN

Check the permissions of the directory.
# ls -lLd <core file directory>
If the has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the core file directory.
# chmod 0700 <core file directory>'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43415r1_chk'
  tag severity: 'low'
  tag gid: 'V-22402'
  tag rid: 'SV-46154r1_rule'
  tag stig_id: 'GEN003504'
  tag gtitle: 'GEN003504'
  tag fix_id: 'F-39493r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
