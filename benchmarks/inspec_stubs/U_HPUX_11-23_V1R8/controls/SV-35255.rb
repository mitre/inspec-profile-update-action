control 'SV-35255' do
  title 'The centralized process core dump data directory must be owned by root.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the centralized process core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the owner of the centralized process core dump directory.
# ls -lLd <directory>
If the owner is not root, this is a finding.'
  desc 'fix', 'Change the owner of the centralized process core dump directory to root.

# chown root <directory>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-29236r1_chk'
  tag severity: 'low'
  tag gid: 'V-22400'
  tag rid: 'SV-35255r1_rule'
  tag stig_id: 'GEN003502'
  tag gtitle: 'GEN003502'
  tag fix_id: 'F-26257r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
