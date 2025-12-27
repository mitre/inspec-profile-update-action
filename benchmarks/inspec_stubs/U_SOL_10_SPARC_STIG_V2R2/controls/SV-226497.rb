control 'SV-226497' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Verify system libraries have no extended ACLs. 

# ls -lL /usr/lib/* /lib/* /usr/sfw/lib

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28658r482879_chk'
  tag severity: 'medium'
  tag gid: 'V-226497'
  tag rid: 'SV-226497r603265_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-28646r482880_fix'
  tag 'documentable'
  tag legacy: ['V-22317', 'SV-26377']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
