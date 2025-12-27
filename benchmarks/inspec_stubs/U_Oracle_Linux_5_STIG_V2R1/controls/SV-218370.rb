control 'SV-218370' do
  title 'Public directories must be the only world-writable directories and world-writable files must be located only in public directories.'
  desc 'World-writable files and directories make it easy for a malicious user to place potentially compromising files on the system.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Check the system for world-writable files.

Procedure:
# find / -perm -2 -a \\( -type d -o -type f \\) -exec ls -ld {} \\;

If any world-writable files are located, except those required for system operation such as /tmp and /dev/null, this is a finding.'
  desc 'fix', 'Remove or change the mode for any world-writable file on the system not required to be world-writable.

Procedure:
# chmod o-w <file>

Document all changes'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19845r569068_chk'
  tag severity: 'medium'
  tag gid: 'V-218370'
  tag rid: 'SV-218370r603259_rule'
  tag stig_id: 'GEN002480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19843r569069_fix'
  tag 'documentable'
  tag legacy: ['V-1010', 'SV-63673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
