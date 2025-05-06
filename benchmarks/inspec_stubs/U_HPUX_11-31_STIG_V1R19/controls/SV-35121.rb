control 'SV-35121' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', 'Check the permissions of the file.
# find / -type f -name passwd.nntp | xargs -n1 ls -lL

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.

# chacl -z <path>/passwd.nntp'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22505'
  tag rid: 'SV-35121r1_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'GEN006330'
  tag fix_id: 'F-30273r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
