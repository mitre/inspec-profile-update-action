control 'SV-226489' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28650r482852_chk'
  tag severity: 'medium'
  tag gid: 'V-226489'
  tag rid: 'SV-226489r603265_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-28638r482853_fix'
  tag 'documentable'
  tag legacy: ['V-794', 'SV-794']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
