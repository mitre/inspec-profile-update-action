control 'SV-44952' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', %q(Verify system libraries have no extended ACLs.
# ls -lL /usr/lib/* /usr/lib64/* /lib/* /lib64/* | grep "+ "
If the permissions include a '+', the file has an extended ACL and has not been approved by the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/lib/* /usr/lib64/* /lib/* /lib64/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22317'
  tag rid: 'SV-44952r1_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'GEN001310'
  tag fix_id: 'F-38377r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
