control 'SV-218474' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19949r562576_chk'
  tag severity: 'low'
  tag gid: 'V-218474'
  tag rid: 'SV-218474r603259_rule'
  tag stig_id: 'GEN003521'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19947r562577_fix'
  tag 'documentable'
  tag legacy: ['V-22405', 'SV-64431']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
