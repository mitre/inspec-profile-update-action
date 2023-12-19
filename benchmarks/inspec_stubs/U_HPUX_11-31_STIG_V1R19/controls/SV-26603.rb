control 'SV-26603' do
  title 'The centralized process core dump data directory must not have an extended ACL.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the process core dump data directory has an extended ACL, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', %q(View all coreadm configuration settings.
# coreadm

Or

View only if a directory is defined for process core dumps. If no information is returned, a directory has not been defined.
# coreadm | tr '\011' ' ' | tr -s ' ' | egrep -i "global core file pattern|global core dumps" 

If the process core dump directory is undefined and core dumps are disabled, this is not applicable.

If the process core dump directory is defined and core dumps are enabled, check the permissions of the <core file directory>
# ls -lLd `dirname <core dump directory>`

If the permissions include a "+" the file has an extended ACL, this is a finding.)
  desc 'fix', 'If the core file dump pattern is undefined, ensure that core dumps are disabled.
# coreadm -d global

If the core file dump pattern is defined and core dumps are enabled and the core file directory permissions include a "+" (ACL), remove the optional ACL from the file.
# chacl -z <core file directory>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36492r2_chk'
  tag severity: 'low'
  tag gid: 'V-22403'
  tag rid: 'SV-26603r1_rule'
  tag stig_id: 'GEN003505'
  tag gtitle: 'GEN003505'
  tag fix_id: 'F-31845r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
