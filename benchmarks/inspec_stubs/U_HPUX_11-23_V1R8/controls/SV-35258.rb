control 'SV-35258' do
  title 'The centralized process core dump data directory must not have an extended ACL.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Any data the process was handling may be contained in the core file, and it must be protected accordingly.  If the process core dump data directory has an extended ACL, unauthorized users may be able to view or to modify sensitive information contained any process core dumps in the directory.'
  desc 'check', %q(Coreadm is not available for HP-UX 11i versions prior to 11i-v3 (11.31). When a core dump occurs on 11i-v2, the core is placed in the program's working directory. In order to implement this feature of coreadm, the filesystem would have to be traversed (on a virtually continuous basis) in order to locate a corefile and move it to a manually configured core directory. As there is a prior requirement to disable core dumps via V-11996 :

# echo "ulimit -c 0" >> /etc/profile

This check is currently not applicable to HP-UX 11i-v2.)
  desc 'fix', 'NA'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35094r1_chk'
  tag severity: 'low'
  tag gid: 'V-22403'
  tag rid: 'SV-35258r1_rule'
  tag stig_id: 'GEN003505'
  tag gtitle: 'GEN003505'
  tag fix_id: 'F-30363r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
