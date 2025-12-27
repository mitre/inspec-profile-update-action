control 'SV-46153' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, sys, or system.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Check the defined directory for process core dumps.

Procedure:
# cat /proc/sys/kernel/core_pattern
Check the group ownership of the directory
# ls -lLd <core file directory>
If the directory is not group-owned by root, bin, sys, or system this is a finding.'
  desc 'fix', 'Change the group-owner of the core file directory.
# chgrp root <core file directory>'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43414r1_chk'
  tag severity: 'low'
  tag gid: 'V-22401'
  tag rid: 'SV-46153r1_rule'
  tag stig_id: 'GEN003503'
  tag gtitle: 'GEN003503'
  tag fix_id: 'F-39492r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
