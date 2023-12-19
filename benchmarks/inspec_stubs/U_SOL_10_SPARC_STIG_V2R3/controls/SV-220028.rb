control 'SV-220028' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Check the mode of library files.

Procedure:
# ls -lLR /usr/lib /lib /usr/sfw/lib

If any of the library files have a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of library files to 0755 or less permissive.

Procedure (example):
# chmod 0755 /path/to/library-file

NOTE: Library files should have an extension of .a or .so, possibly followed by a version number.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21737r482876_chk'
  tag severity: 'medium'
  tag gid: 'V-220028'
  tag rid: 'SV-220028r603265_rule'
  tag stig_id: 'GEN001300'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-21736r482877_fix'
  tag 'documentable'
  tag legacy: ['V-793', 'SV-39821']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
