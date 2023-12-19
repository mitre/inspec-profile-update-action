control 'SV-46155' do
  title 'The centralized process core dump data directory must not have an extended ACL.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the process core dump data directory has an extended ACL, unauthorized users may be able to view or to modify sensitive information contained in any process core dumps in the directory.'
  desc 'check', "Check the defined directory for process core dumps.

Procedure:
Check the defined directory for process core dumps.
# cat /proc/sys/kernel/core_pattern|xargs -n1 -IPATTERN dirname PATTERN

Check the permissions of the directory.
# ls -lLd <core file directory>
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <core file directory>'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43416r1_chk'
  tag severity: 'low'
  tag gid: 'V-22403'
  tag rid: 'SV-46155r1_rule'
  tag stig_id: 'GEN003505'
  tag gtitle: 'GEN003505'
  tag fix_id: 'F-39494r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
