control 'SV-227788' do
  title 'The kernel core dump data directory must be group-owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the kernel core dump data directory. 

# dumpadm | grep "Savecore directory"
OR
# grep DUMPADM_SAVDIR /etc/dumpadm.conf

Check ownership of the core dump data directory.
# ls -l [savecore directory]
If the directory is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the kernel core dump data directory.
# chgrp root [kernel core dump data directory]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29950r489718_chk'
  tag severity: 'low'
  tag gid: 'V-227788'
  tag rid: 'SV-227788r603266_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29938r489719_fix'
  tag 'documentable'
  tag legacy: ['V-22405', 'SV-26610']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
