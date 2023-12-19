control 'SV-26616' do
  title 'The kernel core dump data directory must not have an extended ACL.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If there is an extended ACL for the kernel core dump data directory, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', "Determine the kernel core dump data directory and check its permissions.

Procedure:
Verify the location of the kernel core dump data directory:
# grep “path” /etc/kdump.conf

Note: If this setting is not configured or commented out, the default kernel dump data directory is /var/crash.

Check the permissions of the dump data directory:
# ls -ld <path to kernel core dump data directory>

If the permissions include a '+', the directory has an extended ACL. If the directory has an extended ACL and it has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the directory.
# setfacl --remove-all <path to kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36352r2_chk'
  tag severity: 'low'
  tag gid: 'V-22407'
  tag rid: 'SV-26616r2_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'GEN003523'
  tag fix_id: 'F-23859r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
