control 'SV-235002' do
  title 'All SUSE operating system world-writable directories must be group-owned by root, sys, bin, or an application group.'
  desc 'If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Verify all SUSE operating system world-writable directories are group-owned by root, sys, bin, or an application group.

Check the system for world-writable directories with the following command:

> sudo find / -perm -002 -type d -exec ls -lLd {} \\;
drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue
drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm
drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp

If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding.'
  desc 'fix', 'Change the group of the SUSE operating system world-writable directories to root with the following command:

> sudo chgrp root <directory>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38190r619275_chk'
  tag severity: 'medium'
  tag gid: 'V-235002'
  tag rid: 'SV-235002r622137_rule'
  tag stig_id: 'SLES-15-040180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38153r619276_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
