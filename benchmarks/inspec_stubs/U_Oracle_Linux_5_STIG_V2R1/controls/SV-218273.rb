control 'SV-218273' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Check the mode of library files.

Procedure:
# DIRS="/usr/lib /lib /usr/lib64 /lib64";for DIR in $DIRS;do find $DIR -type f -perm +022 -exec stat -c %a:%n {} \\;;done

This will return the octal permissions and name of all group or world writable files.
If any file listed is world or group writable (either or both of the 2 lowest order digits contain a 2, 3 or 6), this is a finding.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod go-w </path/to/library-file>

Note: Library files should have an extension of ".a" or a ".so" extension, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19748r554156_chk'
  tag severity: 'medium'
  tag gid: 'V-218273'
  tag rid: 'SV-218273r603259_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19746r554157_fix'
  tag 'documentable'
  tag legacy: ['V-793', 'SV-64525']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
