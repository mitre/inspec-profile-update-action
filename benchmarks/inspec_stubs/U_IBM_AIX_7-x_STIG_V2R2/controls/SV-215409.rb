control 'SV-215409' do
  title 'AIX public directories must be the only world-writable directories and world-writable files must be located only in public directories.'
  desc 'World-writable files and directories make it easy for a malicious user to place potentially compromising files on the system. The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage (e.g., /tmp) and for directories requiring global read/write access.'
  desc 'check', 'Check the system for world-writable files and directories by running command:
# find / -perm -2 -a \\( -type d -o -type f \\) -exec ls -ld {} \\; 

If any world-writable files or directories are located, except those required for proper system or application operation, such as "/tmp" and "/dev/null", this is a finding.'
  desc 'fix', 'Remove or change the mode for any world-writable file or directory on the system that is not required to be world-writable by running command: 
# chmod o-w <file/directory> 

Document all changes.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16607r294678_chk'
  tag severity: 'medium'
  tag gid: 'V-215409'
  tag rid: 'SV-215409r508663_rule'
  tag stig_id: 'AIX7-00-003111'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16605r294679_fix'
  tag 'documentable'
  tag legacy: ['SV-101743', 'V-91645']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
