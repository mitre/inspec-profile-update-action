control 'SV-216215' do
  title 'The kernel core dump data directory must be group-owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not group-owned by a system group, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'The root role is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the location of the system dump directory.

# dumpadm | grep directory

Check ownership of the core dump data directory.

# ls -l [savecore directory]

If the directory is not group-owned by root, this is a finding.

In Solaris 11, /var/crash is linked to /var/share/crash.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Determine the location of the system dump directory.

# dumpadm | grep directory

Change the group-owner of the kernel core dump data directory. 

# chgrp root [kernel core dump data directory]

In Solaris 11, /var/crash is linked to /var/share/crash.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17453r373027_chk'
  tag severity: 'medium'
  tag gid: 'V-216215'
  tag rid: 'SV-216215r603268_rule'
  tag stig_id: 'SOL-11.1-080100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17451r373028_fix'
  tag 'documentable'
  tag legacy: ['V-48009', 'SV-60881']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
