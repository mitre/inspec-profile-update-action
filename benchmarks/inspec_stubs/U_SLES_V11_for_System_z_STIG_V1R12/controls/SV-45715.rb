control 'SV-45715' do
  title 'The kernel core dump data directory must not have an extended ACL.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If there is an extended ACL for the kernel core dump data directory, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', "Determine the kernel core dump data directory and check its permissions.
# ls -ld /var/crash
If the permissions include a '+' the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/crash'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43081r1_chk'
  tag severity: 'low'
  tag gid: 'V-22407'
  tag rid: 'SV-45715r1_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'GEN003523'
  tag fix_id: 'F-39113r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
