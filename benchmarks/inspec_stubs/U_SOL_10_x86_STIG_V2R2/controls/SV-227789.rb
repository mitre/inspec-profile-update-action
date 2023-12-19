control 'SV-227789' do
  title 'The kernel core dump data directory must have mode 0700 or less permissive.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the mode of the kernel core dump data directory is more permissive than 0700, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'Determine the kernel core dump data directory. 

# dumpadm | grep "Savecore directory"
OR
# grep DUMPADM_SAVDIR /etc/dumpadm.conf

Check the permissions of the kernel core dump data directory.
# ls -l [savecore directory]
If the directory has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the group-owner of the kernel core dump data directory.
# chmod 0700 [kernel core dump data directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29951r489721_chk'
  tag severity: 'low'
  tag gid: 'V-227789'
  tag rid: 'SV-227789r603266_rule'
  tag stig_id: 'GEN003522'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29939r489722_fix'
  tag 'documentable'
  tag legacy: ['V-22406', 'SV-26614']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
