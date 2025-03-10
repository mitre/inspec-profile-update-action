control 'SV-227945' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/passwd.nntp
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30107r490255_chk'
  tag severity: 'medium'
  tag gid: 'V-227945'
  tag rid: 'SV-227945r603266_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30095r490256_fix'
  tag 'documentable'
  tag legacy: ['V-22505', 'SV-26850']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
