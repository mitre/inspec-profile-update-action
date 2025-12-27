control 'SV-45708' do
  title 'The kernel core dump data directory must be group-owned by root, bin, sys, or system.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the kernel core dump data directory and check its ownership.
# ls -ld /var/crash
If the directory is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group-owner of the kernel core dump data directory.
# chgrp root /var/crash'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43074r1_chk'
  tag severity: 'low'
  tag gid: 'V-22405'
  tag rid: 'SV-45708r1_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'GEN003521'
  tag fix_id: 'F-39107r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
