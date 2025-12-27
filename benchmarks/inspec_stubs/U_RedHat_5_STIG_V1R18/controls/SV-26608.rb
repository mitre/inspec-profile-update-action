control 'SV-26608' do
  title 'The kernel core dump data directory must be group-owned by root, bin, sys, or system.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly.  If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the kernel core dump data directory and check its ownership.

Procedure:
Examine /etc/kdump.conf. The "path" parameter, which defaults to /var/crash, determines the path relative to the crash dump device. The crash device is specified with a filesystem type and device, such as "ext3 /dev/sda2". Using this information, determine where this path is currently mounted on the system.
# ls -ld <kernel dump data directory>
If the directory is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the kernel core dump data directory.
# chgrp root <kernel core dump data directory>'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27647r1_chk'
  tag severity: 'low'
  tag gid: 'V-22405'
  tag rid: 'SV-26608r1_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'GEN003521'
  tag fix_id: 'F-31609r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
