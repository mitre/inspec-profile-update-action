control 'SV-26580' do
  title 'The centralized process core dump data directory must be owned by root.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the centralized process core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', %q(View all coreadm configuration settings.
# coreadm

Or

View only if a directory is defined for process core dumps. If no information is returned, a directory has not been defined.
# coreadm | tr '\011' ' ' | tr -s ' ' | egrep -i "global core file pattern|global core dumps" 

If the process core dump directory is undefined and core dumps are disabled, this is not applicable.

To check the ownership of the <core file directory>,  substitute the global core file pattern from the above command into the next command.
# ls -lLd `dirname <global core file pattern>`

If the directory is not owned by root, this is a finding.)
  desc 'fix', 'If the core file dump pattern is undefined, ensure that core dumps are disabled.
# coreadm -d global

If the core file dump pattern is defined and core dumps are enabled and the core file directory is not group-owned by root, bin, sys or other, change the owner of the core file directory.
# chown root <core file directory>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36489r2_chk'
  tag severity: 'low'
  tag gid: 'V-22400'
  tag rid: 'SV-26580r1_rule'
  tag stig_id: 'GEN003502'
  tag gtitle: 'GEN003502'
  tag fix_id: 'F-31841r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
