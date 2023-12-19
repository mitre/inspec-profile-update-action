control 'SV-35254' do
  title 'The system must be configured to store any process core dumps in a specific, centralized directory.'
  desc 'Specifying a centralized location for core file creation allows for the centralized protection of core files.  Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If process core dump creation is not configured to use a centralized directory, core dumps may be created in a directory without appropriate ownership or permissions configured, which could result in unauthorized access to the core dumps.'
  desc 'check', 'Determine if the system is configured to create process core dumps in a specific, centralized directory. If not, this is a finding.'
  desc 'fix', 'Configure the system to create process core dumps only in a specific, centralized location.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-29234r1_chk'
  tag severity: 'low'
  tag gid: 'V-22399'
  tag rid: 'SV-35254r1_rule'
  tag stig_id: 'GEN003501'
  tag gtitle: 'GEN003501'
  tag fix_id: 'F-26255r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
