control 'SV-216216' do
  title 'The kernel core dump data directory must have mode 0700 or less permissive.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. As the system memory may contain sensitive information, it must be protected accordingly. If the mode of the kernel core dump data directory is more permissive than 0700, unauthorized users may be able to view or to modify kernel core dump data files.'
  desc 'check', 'The root role is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the location of the system dump directory.

# dumpadm | grep directory

Check the permissions of the kernel core dump data directory.

# ls -ld [savecore directory]

If the directory has a mode more permissive than 0700 (rwx --- ---), this is a finding.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Determine the location of the system dump directory.

# dumpadm | grep directory

Change the group-owner of the kernel core dump data directory. 

# chmod 0700 [savecore directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17454r373030_chk'
  tag severity: 'medium'
  tag gid: 'V-216216'
  tag rid: 'SV-216216r603268_rule'
  tag stig_id: 'SOL-11.1-080110'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17452r373031_fix'
  tag 'documentable'
  tag legacy: ['SV-60879', 'V-48007']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
