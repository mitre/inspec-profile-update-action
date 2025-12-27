control 'SV-26066' do
  title 'The kernel core dump data directory must be group-owned by root, bin, sys, or system.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the group owner of the kernel core dump data directory.
# ls -lLd <directory>
If the group owner is not root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the kernel core dump data directory to root, bin, sys, or system.
# chgrp root <directory>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29243r1_chk'
  tag severity: 'low'
  tag gid: 'V-22405'
  tag rid: 'SV-26066r1_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'GEN003521'
  tag fix_id: 'F-26262r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
