control 'SV-44951' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Check the mode of library files.

Procedure:
# DIRS="/usr/lib /usr/lib64 /lib /lib64";for DIR in $DIRS;do find $DIR -type f -perm +022 -exec stat -c %a:%n {} \\;;done

This will return the octal permissions and name of all group or world writable files.
If any file listed is world or group writable (either or both of the 2 lowest order digits contain a 2, 3 or 6), this is a finding.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod go-w </path/to/library-file>

Note: Library files should have an extension of ".a" or a ".so" extension, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42378r1_chk'
  tag severity: 'medium'
  tag gid: 'V-793'
  tag rid: 'SV-44951r1_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'GEN001300'
  tag fix_id: 'F-38376r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
