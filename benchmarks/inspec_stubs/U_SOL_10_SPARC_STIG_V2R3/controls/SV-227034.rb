control 'SV-227034' do
  title 'The /etc/news/hosts.nntp.nolimit file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/hosts.nntp.nolimit
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/news/hosts.nntp.nolimit'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29196r485456_chk'
  tag severity: 'medium'
  tag gid: 'V-227034'
  tag rid: 'SV-227034r603265_rule'
  tag stig_id: 'GEN006290'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29184r485457_fix'
  tag 'documentable'
  tag legacy: ['V-22503', 'SV-26842']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
