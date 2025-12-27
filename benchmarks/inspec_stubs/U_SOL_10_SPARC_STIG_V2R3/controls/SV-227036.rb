control 'SV-227036' do
  title 'The /etc/news/nnrp.access file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/nnrp.access
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/news/nnrp.access'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29198r485462_chk'
  tag severity: 'medium'
  tag gid: 'V-227036'
  tag rid: 'SV-227036r603265_rule'
  tag stig_id: 'GEN006310'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29186r485463_fix'
  tag 'documentable'
  tag legacy: ['SV-26846', 'V-22504']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
