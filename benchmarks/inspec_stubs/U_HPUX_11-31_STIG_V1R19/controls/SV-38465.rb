control 'SV-38465' do
  title 'All system command files must have mode 755 or less permissive.'
  desc "Restricting permissions will protect system command files from unauthorized modification. System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Check the permissions for files in /etc, /bin, /usr/bin, /usr/lbin, /sbin, and /usr/sbin. 

# ls -lL /etc /bin /usr/bin /usr/lbin /sbin /usr/sbin

If any file listed has a mode more permissive than 755, this is a finding.

Note: Elevate to Severity Code I if any file is listed as world-writable.'
  desc 'fix', 'Change the mode for system command files to 755 or less permissive.

# chmod 755 <filename>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36308r1_chk'
  tag severity: 'medium'
  tag gid: 'V-794'
  tag rid: 'SV-38465r1_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'GEN001200'
  tag fix_id: 'F-31563r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Elevate to Severity Code I if any file listed world-writable.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
