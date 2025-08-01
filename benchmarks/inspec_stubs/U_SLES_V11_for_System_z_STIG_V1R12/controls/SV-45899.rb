control 'SV-45899' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/news/passwd.nntp
If the mode includes a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43210r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22505'
  tag rid: 'SV-45899r1_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'GEN006330'
  tag fix_id: 'F-39278r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
