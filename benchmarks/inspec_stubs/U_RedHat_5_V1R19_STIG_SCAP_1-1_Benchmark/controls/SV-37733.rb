control 'SV-37733' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22505'
  tag rid: 'SV-37733r1_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'GEN006330'
  tag fix_id: 'F-32194r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
