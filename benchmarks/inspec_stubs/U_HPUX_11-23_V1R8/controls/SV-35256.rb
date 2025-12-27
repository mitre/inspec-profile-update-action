control 'SV-35256' do
  title 'The centralized process core dump data directory must be group-owned by root, bin, sys, or system.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the group owner of the centralized process core dump directory.
# ls -lLd <directory>
If the group owner is not root, bin, sys, or system, this is a finding.'
  desc 'fix', 'NA'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-29237r1_chk'
  tag severity: 'low'
  tag gid: 'V-22401'
  tag rid: 'SV-35256r1_rule'
  tag stig_id: 'GEN003503'
  tag gtitle: 'GEN003503'
  tag fix_id: 'F-30361r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
