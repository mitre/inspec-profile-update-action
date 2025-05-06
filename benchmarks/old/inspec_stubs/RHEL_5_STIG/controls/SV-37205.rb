control 'SV-37205' do
  title 'All system command files must have mode 0755 or less permissive.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'fix', 'Change the mode for system command files to 0755 or less permissive taking into account necessary GIUD and SUID bits.

Procedure:
# chmod go-w <filename>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-794'
  tag rid: 'SV-37205r2_rule'
  tag stig_id: 'GEN001200'
  tag gtitle: 'GEN001200'
  tag fix_id: 'F-31155r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Elevate to Severity Code I if any file listed world-writable.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
