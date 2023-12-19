control 'SV-26619' do
  title 'The kernel core dump data directory must not have an extended ACL.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. As the system memory may contain sensitive information, it must be protected accordingly. If there is an extended ACL for the kernel core dump data directory, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'Determine the kernel core dump data directory and check its permissions.
# ls -lLd /var/adm/crash

If the permissions include a "+"  the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /var/adm/crash'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36497r1_chk'
  tag severity: 'low'
  tag gid: 'V-22407'
  tag rid: 'SV-26619r1_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'GEN003523'
  tag fix_id: 'F-31852r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
