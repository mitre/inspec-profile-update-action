control 'SV-26180' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/passwd.nntp
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/news/passwd.nntp file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27820r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22505'
  tag rid: 'SV-26180r1_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'GEN006330'
  tag fix_id: 'F-26311r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
