control 'SV-45894' do
  title 'The /etc/news/hosts.nntp.nolimit file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', %q(Check the permissions for "/etc/news/hosts.nntp.nolimit".

# ls -lL /etc/news/hosts.nntp.nolimit
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43206r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22503'
  tag rid: 'SV-45894r1_rule'
  tag stig_id: 'GEN006290'
  tag gtitle: 'GEN006290'
  tag fix_id: 'F-39272r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
