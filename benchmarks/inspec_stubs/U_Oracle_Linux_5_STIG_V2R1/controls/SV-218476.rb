control 'SV-218476' do
  title 'The kernel core dump data directory must not have an extended ACL.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If there is an extended ACL for the kernel core dump data directory, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', %q(Determine the kernel core dump data directory and check its permissions.

Procedure:
Verify the location of the kernel core dump data directory:
# grep "path" /etc/kdump.conf

Note: If this setting is not configured or commented out, the default kernel dump data directory is /var/crash.

Check the permissions of the dump data directory:
# ls -ld <path to kernel core dump data directory>

If the permissions include a '+', the directory has an extended ACL. If the directory has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the directory.

# setfacl --remove-all <path to kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19951r562582_chk'
  tag severity: 'low'
  tag gid: 'V-218476'
  tag rid: 'SV-218476r603259_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19949r562583_fix'
  tag 'documentable'
  tag legacy: ['V-22407', 'SV-64437']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
