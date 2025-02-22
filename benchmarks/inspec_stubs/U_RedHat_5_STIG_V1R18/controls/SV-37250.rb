control 'SV-37250' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', %q(Verify system libraries have no extended ACLs.

# ls -lLR /usr/lib/ /lib/ /usr/lib64 /lib64 | grep "+ "

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and has not been approved by the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/lib/* /lib/*'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35940r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22317'
  tag rid: 'SV-37250r2_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'GEN001310'
  tag fix_id: 'F-31197r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
