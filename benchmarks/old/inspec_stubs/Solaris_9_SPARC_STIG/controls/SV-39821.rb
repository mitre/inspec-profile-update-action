control 'SV-39821' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod 0755 /path/to/library-file

NOTE: Library files should have an extension of .a or .so, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-793'
  tag rid: 'SV-39821r1_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'GEN001300'
  tag fix_id: 'F-947r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
