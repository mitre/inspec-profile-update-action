control 'SV-226885' do
  title 'The kernel core dump data directory must not have an extended ACL.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If there is an extended ACL for the kernel core dump data directory, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'Determine the kernel core dump data directory.

# dumpadm | grep "Savecore directory"
OR
# grep DUMPADM_SAVDIR /etc/dumpadm.conf

Check the kernel core dump data directory permissions.
# ls -ld [savecore directory]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [kernel core dump directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29047r484939_chk'
  tag severity: 'low'
  tag gid: 'V-226885'
  tag rid: 'SV-226885r603265_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29035r484940_fix'
  tag 'documentable'
  tag legacy: ['SV-26618', 'V-22407']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
