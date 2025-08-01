control 'SV-218265' do
  title 'All system command files must have mode 0755 or less permissive.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Check the permissions for files in /etc, /bin, /usr/bin, /usr/lbin, /usr/ucb, /sbin, and /usr/sbin.

Procedure:
# DIRS="/etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin";for DIR in $DIRS;do find $DIR -type f -perm +022 -exec stat -c %a:%n {} \\;;done

This will return the octal permissions and name of all group or world writable files. If any command file is listed and is world or group writable (either or both of the 2 lowest order digits contain a 2, 3, or 6), this is a finding.

Note: Elevate to Severity Code I if any command file listed is world writable.'
  desc 'fix', 'Change the mode for system command files to 0755 or less permissive taking into account necessary GIUD and SUID bits.

Procedure:
# chmod go-w <filename>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19740r568708_chk'
  tag severity: 'medium'
  tag gid: 'V-218265'
  tag rid: 'SV-218265r603259_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19738r568709_fix'
  tag 'documentable'
  tag legacy: ['V-794', 'SV-64477']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
