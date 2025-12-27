control 'SV-45897' do
  title 'The /etc/news/nnrp.access file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/news/nnrp.access
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/nnrp.access'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43208r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22504'
  tag rid: 'SV-45897r1_rule'
  tag stig_id: 'GEN006310'
  tag gtitle: 'GEN006310'
  tag fix_id: 'F-39275r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
