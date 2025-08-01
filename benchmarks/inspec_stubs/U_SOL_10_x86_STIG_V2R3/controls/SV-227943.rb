control 'SV-227943' do
  title 'The /etc/news/nnrp.access file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/nnrp.access
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/news/nnrp.access'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30105r490249_chk'
  tag severity: 'medium'
  tag gid: 'V-227943'
  tag rid: 'SV-227943r603266_rule'
  tag stig_id: 'GEN006310'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30093r490250_fix'
  tag 'documentable'
  tag legacy: ['V-22504', 'SV-26846']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
