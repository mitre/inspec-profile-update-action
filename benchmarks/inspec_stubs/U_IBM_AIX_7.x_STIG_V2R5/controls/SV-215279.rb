control 'SV-215279' do
  title 'AIX library files must have mode 0755 or less permissive.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Check the mode of library files by running the following command:
# ls -lLR /usr/lib /lib 

If any of the library files have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Change the mode of library files to "0755" or less permissive by running the following command: 
# chmod 0755 <path>/<library-file> 

NOTE: Library files should have an extension of .a or .so (a=archive, so=shared object) extension, possibly followed by a version.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16477r294288_chk'
  tag severity: 'medium'
  tag gid: 'V-215279'
  tag rid: 'SV-215279r508663_rule'
  tag stig_id: 'AIX7-00-002088'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16475r294289_fix'
  tag 'documentable'
  tag legacy: ['SV-101575', 'V-91477']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
