control 'SV-26058' do
  title 'The centralized process core dump data directory must not have an extended ACL.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Any data the process was handling may be contained in the core file, and it must be protected accordingly. If the process core dump data directory has an extended ACL, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', "Determine if the centralized process core dump data directory has an extended ACL.
# ls -lLd <directory>
If the permissions contain a '+', there is an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the centralized process core dump data directory.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29240r1_chk'
  tag severity: 'low'
  tag gid: 'V-22403'
  tag rid: 'SV-26058r1_rule'
  tag stig_id: 'GEN003505'
  tag gtitle: 'GEN003505'
  tag fix_id: 'F-26260r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
