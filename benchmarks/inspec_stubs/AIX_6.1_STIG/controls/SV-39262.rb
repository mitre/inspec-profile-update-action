control 'SV-39262' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', 'Check the permissions of the file.

# find / -name passwd.nntp
# ls -lL < passwd.nntp >
If extended permissions are enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the passwd.nntp file.

# acledit < passwd.nntp >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38237r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22505'
  tag rid: 'SV-39262r1_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'GEN006330'
  tag fix_id: 'F-33511r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
