control 'SV-35119' do
  title 'The /etc/news/nnrp.access file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files. Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# find / -type f -name nnrp.access | xargs -n1 ls -lL

If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <path>/nnrp.access'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36714r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22504'
  tag rid: 'SV-35119r1_rule'
  tag stig_id: 'GEN006310'
  tag gtitle: 'GEN006310'
  tag fix_id: 'F-32095r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
