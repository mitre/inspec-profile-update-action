control 'SV-26611' do
  title 'The kernel core dump data directory must be group-owned by root, bin, sys, or other.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'fix', 'Change the group-owner of the kernel core dump data directory.
# chgrp root /var/adm/crash'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22405'
  tag rid: 'SV-26611r1_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'GEN003521'
  tag fix_id: 'F-31849r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
