control 'SV-46272' do
  title 'All system command files must have mode 0755 or less permissive.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Check the permissions for files in /etc, /bin, /usr/bin, /usr/local/bin, /sbin, /usr/sbin and /usr/local/sbin.

Procedure:
# DIRS="/etc /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin";for DIR in $DIRS;do find $DIR -type f -perm +022 -exec stat -c %a:%n {} \\;;done

This will return the octal permissions and name of all group or world writable files. If any file listed is world or group writable (either or both of the 2 lowest order digits contain a 2, 3 or 6), this is a finding.

Note: Elevate to Severity Code I if any file listed is world-writable.'
  desc 'fix', 'Change the mode for system command files to 0755 or less permissive taking into account necessary GUID and SUID bits.

Procedure:
# chmod go-w <filename>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43432r1_chk'
  tag severity: 'medium'
  tag gid: 'V-794'
  tag rid: 'SV-46272r1_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'GEN001200'
  tag fix_id: 'F-39575r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Elevate to Severity Code I if any file listed world-writable.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
