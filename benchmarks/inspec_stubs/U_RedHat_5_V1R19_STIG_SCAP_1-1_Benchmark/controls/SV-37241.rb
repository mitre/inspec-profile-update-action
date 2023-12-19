control 'SV-37241' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod go-w </path/to/library-file>

Note: Library files should have an extension of ".a" or a ".so" extension, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-793'
  tag rid: 'SV-37241r2_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'GEN001300'
  tag fix_id: 'F-31188r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
