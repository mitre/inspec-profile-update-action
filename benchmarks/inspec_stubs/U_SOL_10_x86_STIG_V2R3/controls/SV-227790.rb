control 'SV-227790' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29952r489724_chk'
  tag severity: 'low'
  tag gid: 'V-227790'
  tag rid: 'SV-227790r603266_rule'
  tag stig_id: 'GEN003523'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29940r489725_fix'
  tag 'documentable'
  tag legacy: ['V-22407', 'SV-26618']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
