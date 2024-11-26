control 'SV-1010' do
  title 'Public directories must be the only world-writable directories and world-writable files must be located only in public directories.'
  desc 'World-writable files and directories make it easy for a malicious user to place potentially compromising files on the system.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the system for world-writable files and directories.

Procedure:
# find / -perm -2 -a \\(   -type d -o -type f    \\) -exec ls -ld {} \\;

If any world-writable files or directories are located, except those required for proper system or application operation, such as /tmp and /dev/null, this is a finding.'
  desc 'fix', 'Remove or change the mode for any world-writable file or directory on the system that is not required to be world-writable.

Procedure:
# chmod o-w <file/directory>

Document all changes.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-467r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1010'
  tag rid: 'SV-1010r3_rule'
  tag stig_id: 'GEN002480'
  tag gtitle: 'GEN002480'
  tag fix_id: 'F-1164r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
