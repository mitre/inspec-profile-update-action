control 'SV-26056' do
  title 'The centralized process core dump data directory must have mode 0700 or less permissive.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the process core dump data directory has a mode more permissive than 0700, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', 'Determine the mode of the centralized process core dump data directory.

Procedure:
# ls -lLd <directory>

If the mode is more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the centralized process core dump directory to 0700.
Procedure:
# chmod 0700 <directory>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29239r1_chk'
  tag severity: 'low'
  tag gid: 'V-22402'
  tag rid: 'SV-26056r1_rule'
  tag stig_id: 'GEN003504'
  tag gtitle: 'GEN003504'
  tag fix_id: 'F-26259r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
