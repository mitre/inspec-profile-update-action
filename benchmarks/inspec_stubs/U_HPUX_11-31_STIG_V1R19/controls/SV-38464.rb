control 'SV-38464' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Check the mode of library files.

Procedure:
# ls -lLR /usr/lib /lib

If any of the library files have a mode more permissive than 755, this is a finding.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod 0755 <path>/<library-file>

NOTE: Library files should have an extension of ".a" or ".so" (a=archive, so=shared object) extension, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36307r2_chk'
  tag severity: 'medium'
  tag gid: 'V-793'
  tag rid: 'SV-38464r1_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'GEN001300'
  tag fix_id: 'F-31562r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
