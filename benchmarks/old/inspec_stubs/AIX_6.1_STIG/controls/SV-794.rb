control 'SV-794' do
  title 'All system command files must have mode 755 or less permissive.'
  desc "Restricting permissions will protect system command files from unauthorized modification. System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Check the permissions for files in /etc, /bin, /usr/bin, /usr/lbin, /usr/ucb, /sbin, and /usr/sbin.

Procedure:
# ls -lL /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin

If any command file is listed and has a mode more permissive than 755, this is a finding.

Note: Elevate to Severity Code I if any command file listed is world-writable.'
  desc 'fix', 'Change the mode for system command files to 755 or less permissive.

Procedure:
# chmod 755 <filename>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-298r6_chk'
  tag severity: 'medium'
  tag gid: 'V-794'
  tag rid: 'SV-794r4_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'GEN001200'
  tag fix_id: 'F-948r3_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Elevate to Severity Code I if any file listed is world-writable.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
