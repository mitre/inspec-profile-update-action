control 'SV-38283' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Verify system libraries have no extended ACLs.
# ls -lLR /usr/lib/* /lib/*
If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /usr/lib/* /lib/*'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36316r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22317'
  tag rid: 'SV-38283r1_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'GEN001310'
  tag fix_id: 'F-31571r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
