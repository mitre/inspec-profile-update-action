control 'SV-26583' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, sys, or other.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', %q(View all coreadm configuration settings.
# coreadm

Or

View only if a directory is defined for process core dumps. If no information is returned, a directory has not been defined.
# coreadm | tr '\011' ' ' | tr -s ' ' | egrep -i "global core file pattern|global core dumps" 

If the process core dump directory is undefined and core dumps are disabled, this is not applicable.

Check the group  ownership of the <core file directory>
# ls -lLd `dirname "${CorePathFile}"`

If the process core dump directory is defined and core dumps are enabled and the directory is not group-owned by root, bin, sys, or other, this is a finding.)
  desc 'fix', 'Change the group-owner of the core file directory.
# chgrp root <core file directory>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36490r2_chk'
  tag severity: 'low'
  tag gid: 'V-22401'
  tag rid: 'SV-26583r1_rule'
  tag stig_id: 'GEN003503'
  tag gtitle: 'GEN003503'
  tag fix_id: 'F-31842r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
